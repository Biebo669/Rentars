/**
 * Payment service — canonical state machine for USDC payment intents.
 *
 * State lifecycle (closes #609):
 *
 *   ┌─────────┐
 *   │ pending │  Payment intent created; no transaction submitted yet.
 *   └────┬────┘
 *        │ submitTransaction()
 *        ▼
 *   ┌───────────┐
 *   │ submitted │  Signed XDR delivered to Stellar Horizon; awaiting ledger.
 *   └─────┬─────┘
 *         ├─── confirmTransaction() → ┌───────────┐
 *         │                           │ confirmed │  Ledger sealed; escrow funded.
 *         │                           └───────────┘
 *         ├─── on-chain failure   → ┌────────┐
 *         │                         │ failed │  Terminal; no escrow.
 *         │                         └────────┘
 *         └─── 60 s timeout      → ┌───────────┐
 *                                  │ timed_out │  May be retried.
 *                                  └───────────┘
 *
 * Additional terminal states:
 *   refunded      — escrow cancelled, funds returned to tenant.
 *   under_review  — conflicting update quarantined for manual review.
 *
 * Rules enforced here:
 *  1. Transitions only advance through the allowed graph; regressive moves
 *     are rejected and quarantined as `under_review`.
 *  2. Each event carries a SHA-256 hash of its payload; duplicate hashes
 *     are idempotently replayed without re-applying side-effects.
 *  3. External provider IDs (escrow_id, stellar_tx_hash) are stored so
 *     every payment has a complete, auditable lifecycle.
 *  4. Unknown / unsupported statuses returned by external providers are
 *     quarantined rather than silently accepted.
 */

import { createHash, randomUUID } from 'node:crypto';
import { supabase } from '@/config/supabase.js';
import { auditLogger } from './auditLogger.service.js';
import type { ServiceResponse } from './index.js';

// ─── Types ────────────────────────────────────────────────────────────────────

export type PaymentStatus =
  | 'pending'
  | 'submitted'
  | 'confirmed'
  | 'failed'
  | 'timed_out'
  | 'refunded'
  | 'under_review';

/**
 * Allowed forward transitions in the payment state machine.
 * Any move not listed here is rejected and quarantined.
 */
const ALLOWED_TRANSITIONS: Readonly<Record<PaymentStatus, ReadonlyArray<PaymentStatus>>> = {
  pending:      ['submitted', 'failed'],
  submitted:    ['confirmed', 'failed', 'timed_out'],
  confirmed:    ['refunded'],
  failed:       [],                         // terminal
  timed_out:    ['submitted', 'failed'],    // retryable
  refunded:     [],                         // terminal
  under_review: ['pending', 'failed'],      // admin-only resolution
};

/**
 * External provider statuses mapped to canonical PaymentStatus.
 * Anything not listed is treated as unknown → under_review.
 */
const PROVIDER_STATUS_MAP: Readonly<Record<string, PaymentStatus>> = {
  // Stellar / Horizon
  SUCCESS:   'confirmed',
  FAILED:    'failed',
  NOT_FOUND: 'timed_out',
  // TrustlessWork escrow statuses
  funded:    'confirmed',
  released:  'refunded',
  cancelled: 'failed',
  disputed:  'under_review',
  created:   'pending',
};

export interface Payment {
  id: string;
  booking_id: string;
  tenant_id: string;
  /** Amount in USDC stroops (integer, 1 USDC = 10_000_000 stroops). */
  amount_stroops: bigint;
  /** Supported currency token — currently only USDC. */
  currency: 'USDC';
  stellar_tx_hash: string | null;
  /** TrustlessWork escrow contract ID, if applicable. */
  escrow_id: string | null;
  /** Quote reference hash signed at intent creation (for amount integrity). */
  quote_hash: string | null;
  status: PaymentStatus;
  /** Version counter incremented on every transition (optimistic concurrency). */
  version: number;
  /** SHA-256 of the last event payload that triggered a transition. */
  last_event_hash: string | null;
  created_at: string;
  updated_at: string;
  metadata: Record<string, unknown> | null;
}

export interface CreatePaymentIntentParams {
  bookingId: string;
  tenantId: string;
  /** Amount in USDC stroops (integer). Use amountUsdcToStroops() to convert. */
  amountStroops: bigint;
  /** Quote hash produced by payment.utils.ts#hashQuote() and verified server-side. */
  quoteHash?: string;
  escrowId?: string;
  metadata?: Record<string, unknown>;
}

export interface TransitionResult {
  payment: Payment;
  /** True when the event was a duplicate (same hash) — no side-effects applied. */
  replayed: boolean;
}

/**
 * Kinds of immutable payment events appended to the ledger.
 * Every attempt and state transition is recorded as one of these.
 */
export type PaymentEventType =
  | 'intent_created'
  | 'submitted'
  | 'confirmed'
  | 'failed'
  | 'timed_out'
  | 'refunded'
  | 'under_review'
  | 'provider_callback';

/**
 * Immutable payment-event record. Rows in `payment_events` are append-only:
 * they are never updated or deleted, so the full history of a payment is
 * always reconstructable.
 */
export interface PaymentEvent {
  id: string;
  payment_id: string;
  booking_id: string;
  /** Quote reference hash signed at intent creation, if known. */
  quote_hash: string | null;
  /** External provider name (e.g. 'stellar', 'trustlesswork'). */
  provider: string | null;
  /** Network identifier (e.g. 'stellar:testnet'). */
  network: string | null;
  /** Amount in USDC stroops (exact integer precision). */
  amount_stroops: bigint;
  currency: 'USDC';
  event_type: PaymentEventType;
  /** Canonical status this event asserts (null for pure provider callbacks). */
  status: PaymentStatus | null;
  /** Client-supplied idempotency key; unique per payment. */
  idempotency_key: string;
  /** Correlation ID propagated to every external call for this event. */
  correlation_id: string;
  /** External provider reference (tx hash, escrow id, callback id). */
  external_ref: string | null;
  /** SHA-256 of the redacted payload — duplicate detection. */
  event_hash: string;
  /** Redacted, credential-free event payload. */
  payload: Record<string, unknown>;
  created_at: string;
}

export interface AppendPaymentEventParams {
  paymentId: string;
  eventType: PaymentEventType;
  /** Canonical status asserted by this event. */
  status?: PaymentStatus | null;
  /** Idempotency key; defaults to the event hash when omitted. */
  idempotencyKey?: string;
  /** Correlation ID; generated when omitted. */
  correlationId?: string;
  provider?: string | null;
  network?: string | null;
  externalRef?: string | null;
  /** Raw payload — credentials are redacted before persistence. */
  payload?: Record<string, unknown>;
  actorId?: string;
}

export interface AppendPaymentEventResult {
  event: PaymentEvent;
  /** True when an event with the same idempotency key already existed. */
  replayed: boolean;
  /** Status derived from the full stored event history. */
  derivedStatus: PaymentStatus;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * Produce a stable SHA-256 hex digest of an event payload object.
 * Used to detect duplicate provider callbacks.
 */
export function hashEventPayload(payload: Record<string, unknown>): string {
  const stable = JSON.stringify(payload, Object.keys(payload).sort());
  return createHash('sha256').update(stable).digest('hex');
}

/**
 * Returns true when `from → to` is a permitted transition.
 */
export function isAllowedTransition(from: PaymentStatus, to: PaymentStatus): boolean {
  return ALLOWED_TRANSITIONS[from]?.includes(to) ?? false;
}

/**
 * Map an external provider status string to a canonical PaymentStatus.
 * Returns `under_review` for any unknown value.
 */
export function mapProviderStatus(raw: string): PaymentStatus {
  return PROVIDER_STATUS_MAP[raw] ?? 'under_review';
}

/** Keys whose values must never be persisted in the event ledger. */
const REDACTED_KEY_PATTERN = /(secret|token|password|credential|private[_-]?key|api[_-]?key|authorization|signature)/i;

/**
 * Recursively redact credential-like values from an event payload.
 * Returns a new object; the input is never mutated.
 */
export function redactPayload(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactPayload(item));
  }
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const [key, val] of Object.entries(value as Record<string, unknown>)) {
      out[key] = REDACTED_KEY_PATTERN.test(key) ? '[REDACTED]' : redactPayload(val);
    }
    return out;
  }
  return value;
}

/**
 * Derive the current payment status reproducibly from an ordered list of
 * stored events. Events are replayed through the same transition graph used
 * by the live service, so the result is deterministic for a given history.
 *
 * Out-of-order events are sorted by `created_at` (then id) before replay.
 * Disallowed transitions quarantine to `under_review`, matching live behaviour.
 */
export function deriveStatusFromEvents(events: ReadonlyArray<PaymentEvent>): PaymentStatus {
  const ordered = [...events].sort((a, b) => {
    const byTime = a.created_at.localeCompare(b.created_at);
    return byTime !== 0 ? byTime : a.id.localeCompare(b.id);
  });

  let status: PaymentStatus = 'pending';
  for (const event of ordered) {
    if (!event.status) continue;
    if (event.status === status) continue;
    status = isAllowedTransition(status, event.status) ? event.status : 'under_review';
  }
  return status;
}

// ─── Service functions ────────────────────────────────────────────────────────

/**
 * Create a new payment intent in `pending` state.
 *
 * @returns The newly created Payment record.
 * @throws  On database error.
 */
export async function createPaymentIntent(
  params: CreatePaymentIntentParams,
): Promise<Payment> {
  const { bookingId, tenantId, amountStroops, quoteHash, escrowId, metadata } = params;

  const { data, error } = await supabase
    .from('payments')
    .insert({
      booking_id: bookingId,
      tenant_id: tenantId,
      amount_stroops: amountStroops.toString(), // stored as text to avoid JS bigint loss
      currency: 'USDC',
      status: 'pending',
      escrow_id: escrowId ?? null,
      quote_hash: quoteHash ?? null,
      version: 1,
      last_event_hash: null,
      metadata: metadata ?? null,
    })
    .select()
    .single();

  if (error || !data) {
    throw new Error(`Failed to create payment intent: ${error?.message ?? 'unknown error'}`);
  }

  const payment = rowToPayment(data);

  // Append the genesis event so the ledger is complete from creation.
  await appendPaymentEvent({
    paymentId: payment.id,
    eventType: 'intent_created',
    status: 'pending',
    provider: escrowId ? 'trustlesswork' : 'stellar',
    network: metadata?.network as string | undefined ?? null,
    externalRef: escrowId ?? null,
    payload: { bookingId, amountStroops: amountStroops.toString(), quoteHash },
    actorId: tenantId,
  });

  await auditLogger.log({
    actorId: tenantId,
    action: 'payment.submit',
    resourceType: 'payment',
    resourceId: payment.id,
    meta: { bookingId, amountStroops: amountStroops.toString() },
  });

  return payment;
}

/**
 * Append an immutable payment event to the ledger.
 *
 * Algorithm:
 *  1. Load the payment to resolve booking/quote/amount context.
 *  2. Redact credentials from the payload and compute its event hash.
 *  3. Resolve the idempotency key (defaults to the event hash).
 *  4. If an event with that key already exists → return it as a replay.
 *  5. Insert the event (append-only; never updates prior rows).
 *  6. Re-derive the current status from the full stored history.
 *
 * @returns The stored event, replay flag, and derived status.
 */
export async function appendPaymentEvent(
  params: AppendPaymentEventParams,
): Promise<AppendPaymentEventResult> {
  const {
    paymentId,
    eventType,
    status = null,
    provider = null,
    network = null,
    externalRef = null,
    payload = {},
    actorId,
  } = params;

  const payment = await getPaymentStatus(paymentId);
  if (!payment) {
    throw new Error(`Cannot append payment event: payment ${paymentId} not found`);
  }

  const redacted = redactPayload(payload) as Record<string, unknown>;
  const eventHash = hashEventPayload({
    paymentId,
    eventType,
    status,
    externalRef,
    payload: redacted,
  });
  const idempotencyKey = params.idempotencyKey ?? eventHash;
  const correlationId = params.correlationId ?? randomUUID();

  // ── Idempotency: same key → return existing event, no new row ─────────────
  const { data: existing } = await supabase
    .from('payment_events')
    .select()
    .eq('payment_id', paymentId)
    .eq('idempotency_key', idempotencyKey)
    .maybeSingle();

  if (existing) {
    const events = await listPaymentEvents(paymentId);
    return {
      event: rowToPaymentEvent(existing),
      replayed: true,
      derivedStatus: deriveStatusFromEvents(events),
    };
  }

  const { data, error } = await supabase
    .from('payment_events')
    .insert({
      payment_id: paymentId,
      booking_id: payment.booking_id,
      quote_hash: payment.quote_hash,
      provider,
      network,
      amount_stroops: payment.amount_stroops.toString(),
      currency: payment.currency,
      event_type: eventType,
      status,
      idempotency_key: idempotencyKey,
      correlation_id: correlationId,
      external_ref: externalRef,
      event_hash: eventHash,
      payload: redacted,
    })
    .select()
    .single();

  if (error || !data) {
    // Unique-constraint race: another writer inserted the same key first.
    if (error?.code === '23505') {
      const events = await listPaymentEvents(paymentId);
      const { data: raced } = await supabase
        .from('payment_events')
        .select()
        .eq('payment_id', paymentId)
        .eq('idempotency_key', idempotencyKey)
        .single();
      if (raced) {
        return {
          event: rowToPaymentEvent(raced),
          replayed: true,
          derivedStatus: deriveStatusFromEvents(events),
        };
      }
    }
    throw new Error(`Failed to append payment event: ${error?.message ?? 'unknown error'}`);
  }

  const events = await listPaymentEvents(paymentId);

  await auditLogger.log({
    actorId,
    action: 'payment.submit',
    resourceType: 'payment',
    resourceId: paymentId,
    meta: { eventType, correlationId, externalRef, idempotencyKey },
  });

  return {
    event: rowToPaymentEvent(data),
    replayed: false,
    derivedStatus: deriveStatusFromEvents(events),
  };
}

/**
 * List all stored events for a payment, ordered oldest-first.
 */
export async function listPaymentEvents(paymentId: string): Promise<PaymentEvent[]> {
  const { data, error } = await supabase
    .from('payment_events')
    .select()
    .eq('payment_id', paymentId)
    .order('created_at', { ascending: true })
    .order('id', { ascending: true });

  if (error) {
    throw new Error(`Failed to list payment events: ${error.message}`);
  }
  return (data ?? []).map(rowToPaymentEvent);
}

/**
 * Derive the current status of a payment from its stored event history.
 * This is the reproducible source of truth for reconciliation.
 */
export async function getDerivedPaymentStatus(paymentId: string): Promise<PaymentStatus | null> {
  const events = await listPaymentEvents(paymentId);
  if (events.length === 0) return null;
  return deriveStatusFromEvents(events);
}

/**
 * Transition a payment to a new status with full idempotency and conflict
 * quarantine.
 *
 * Algorithm:
 *  1. Load current payment with optimistic version.
 *  2. Hash the incoming event payload.
 *  3. If `last_event_hash` matches → replay without side-effects.
 *  4. Verify the transition is allowed; if not → quarantine to `under_review`.
 *  5. Apply the update with version increment; on version conflict retry once.
 *
 * @param paymentId    - UUID of the payment to transition.
 * @param newStatus    - Target status.
 * @param eventPayload - Raw event data (used for duplicate detection).
 * @param txHash       - Optional Stellar transaction hash to record.
 * @param actorId      - Optional actor UUID for audit (omit for system actions).
 *
 * @returns TransitionResult containing updated Payment and replayed flag.
 */
export async function transitionPaymentStatus(
  paymentId: string,
  newStatus: PaymentStatus,
  eventPayload: Record<string, unknown>,
  txHash?: string | null,
  actorId?: string,
): Promise<ServiceResponse<TransitionResult>> {
  const payment = await getPaymentStatus(paymentId);
  if (!payment) {
    return { success: false, error: 'Payment not found' };
  }

  const eventHash = hashEventPayload(eventPayload);

  // ── Idempotency: same event hash → replay without side-effects ────────────
  if (payment.last_event_hash === eventHash) {
    return {
      success: true,
      data: { payment, replayed: true },
    };
  }

  // ── Idempotency: same idempotency key already in the ledger ───────────────
  const idempotencyKey =
    typeof eventPayload.idempotency_key === 'string'
      ? eventPayload.idempotency_key
      : eventHash;
  const { data: existingEvent } = await supabase
    .from('payment_events')
    .select('id')
    .eq('payment_id', paymentId)
    .eq('idempotency_key', idempotencyKey)
    .maybeSingle();
  if (existingEvent) {
    return {
      success: true,
      data: { payment, replayed: true },
    };
  }

  // ── Validate transition ────────────────────────────────────────────────────
  let targetStatus: PaymentStatus = newStatus;
  let quarantineReason: string | undefined;

  if (!isAllowedTransition(payment.status, newStatus)) {
    // Unknown or regressive transition → quarantine
    targetStatus = 'under_review';
    quarantineReason = `Disallowed transition: ${payment.status} → ${newStatus}`;
  }

  // ── Persist with optimistic concurrency ───────────────────────────────────
  const updatePayload: Record<string, unknown> = {
    status: targetStatus,
    version: payment.version + 1,
    last_event_hash: eventHash,
    updated_at: new Date().toISOString(),
  };
  if (txHash !== undefined) updatePayload.stellar_tx_hash = txHash;
  if (quarantineReason) {
    // Store quarantine reason in metadata for manual review
    updatePayload.metadata = {
      ...(payment.metadata ?? {}),
      quarantine_reason: quarantineReason,
      quarantined_at: new Date().toISOString(),
    };
  }

  const { data, error } = await supabase
    .from('payments')
    .update(updatePayload)
    .eq('id', paymentId)
    .eq('version', payment.version) // optimistic concurrency guard
    .select()
    .single();

  if (error || !data) {
    // Version conflict — another process transitioned first
    return {
      success: false,
      error: `Concurrent payment transition conflict for ${paymentId}: ${error?.message ?? 'version mismatch'}`,
    };
  }

  const updated = rowToPayment(data);

  // ── Append immutable ledger event (history is never overwritten) ──────────
  const eventType: PaymentEventType =
    targetStatus === 'under_review' ? 'under_review' : (targetStatus as PaymentEventType);
  await appendPaymentEvent({
    paymentId,
    eventType,
    status: targetStatus,
    idempotencyKey,
    correlationId:
      typeof eventPayload.correlation_id === 'string' ? eventPayload.correlation_id : undefined,
    provider: typeof eventPayload.provider === 'string' ? eventPayload.provider : null,
    network: typeof eventPayload.network === 'string' ? eventPayload.network : null,
    externalRef: txHash ?? null,
    payload: eventPayload,
    actorId,
  });

  // ── Audit ─────────────────────────────────────────────────────────────────
  const auditAction =
    targetStatus === 'confirmed'  ? ('payment.confirmed' as const) :
    targetStatus === 'failed'     ? ('payment.failed'    as const) :
    targetStatus === 'refunded'   ? ('payment.failed'    as const) :
    ('payment.submit' as const);

  await auditLogger.log({
    actorId,
    action: auditAction,
    resourceType: 'payment',
    resourceId: paymentId,
    meta: {
      fromStatus: payment.status,
      toStatus: targetStatus,
      txHash,
      quarantineReason,
    },
  });

  // Alert on quarantine
  if (targetStatus === 'under_review') {
    console.error(
      `[Payment] QUARANTINE paymentId=${paymentId} reason="${quarantineReason}" payload=%j`,
      eventPayload,
    );
  }

  return {
    success: true,
    data: { payment: updated, replayed: false },
  };
}

/**
 * @deprecated Use transitionPaymentStatus() instead.
 *
 * Retained for backward-compatibility with stellar.service.ts callers that
 * have not yet been migrated to the new API.
 */
export async function updatePaymentStatus(
  paymentId: string,
  txHash: string | null,
  status: PaymentStatus,
): Promise<Payment> {
  const result = await transitionPaymentStatus(
    paymentId,
    status,
    { txHash, status, _source: 'stellar_confirmation' },
    txHash,
  );

  if (!result.success || !result.data) {
    throw new Error(result.error ?? 'Failed to update payment status');
  }

  return result.data.payment;
}

/**
 * Get a payment record by ID. Returns null if not found.
 */
export async function getPaymentStatus(paymentId: string): Promise<Payment | null> {
  const { data } = await supabase
    .from('payments')
    .select()
    .eq('id', paymentId)
    .single();
  return data ? rowToPayment(data) : null;
}

/**
 * Get a payment record by booking ID. Returns null if not found.
 */
export async function getPaymentByBookingId(bookingId: string): Promise<Payment | null> {
  const { data } = await supabase
    .from('payments')
    .select()
    .eq('booking_id', bookingId)
    .single();
  return data ? rowToPayment(data) : null;
}

// ─── Row mapping ──────────────────────────────────────────────────────────────

/**
 * Map a raw Supabase row to a typed Payment, handling BigInt conversion.
 */
/**
 * Map a raw Supabase row from `payment_events` to a typed PaymentEvent.
 */
// biome-ignore lint/suspicious/noExplicitAny: raw Supabase row
function rowToPaymentEvent(row: any): PaymentEvent {
  return {
    id:              row.id,
    payment_id:      row.payment_id,
    booking_id:      row.booking_id,
    quote_hash:      row.quote_hash ?? null,
    provider:        row.provider ?? null,
    network:         row.network ?? null,
    amount_stroops:  BigInt(row.amount_stroops ?? 0),
    currency:        row.currency ?? 'USDC',
    event_type:      row.event_type as PaymentEventType,
    status:          (row.status as PaymentStatus | null) ?? null,
    idempotency_key: row.idempotency_key,
    correlation_id:  row.correlation_id,
    external_ref:    row.external_ref ?? null,
    event_hash:      row.event_hash,
    payload:         row.payload ?? {},
    created_at:      row.created_at,
  };
}

// biome-ignore lint/suspicious/noExplicitAny: raw Supabase row
function rowToPayment(row: any): Payment {
  return {
    id:               row.id,
    booking_id:       row.booking_id,
    tenant_id:        row.tenant_id,
    amount_stroops:   BigInt(row.amount_stroops ?? row.amount_usdc ?? 0),
    currency:         row.currency ?? 'USDC',
    stellar_tx_hash:  row.stellar_tx_hash ?? null,
    escrow_id:        row.escrow_id ?? null,
    quote_hash:       row.quote_hash ?? null,
    status:           row.status as PaymentStatus,
    version:          row.version ?? 1,
    last_event_hash:  row.last_event_hash ?? null,
    created_at:       row.created_at,
    updated_at:       row.updated_at,
    metadata:         row.metadata ?? null,
  };
}

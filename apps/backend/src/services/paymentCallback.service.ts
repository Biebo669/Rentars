/**
 * Payment callback verification service (#610).
 *
 * Defends against:
 *  - Forged signatures  — HMAC-SHA256 over raw request bytes
 *  - Replay attacks     — persisted event-ID ledger with TTL
 *  - Clock skew         — reject events older than MAX_CLOCK_SKEW_MS
 *  - Out-of-order       — tolerated; idempotency in state machine handles it
 *  - Cross-booking      — validate payload booking/amount against DB record
 *  - Unknown payloads   — quarantine via transitionPaymentStatus()
 *
 * Provider responses follow HTTP semantics:
 *  - 200 with { status: 'acknowledged' } on valid new event
 *  - 200 with { status: 'replayed' } on recognised duplicate
 *  - 400 on malformed payload
 *  - 401 on invalid / missing signature
 *  - 422 on semantic mismatch (wrong booking / amount)
 *
 * Internal error details are never surfaced to the provider to avoid
 * information leakage.
 */

import { createHmac, timingSafeEqual, randomUUID } from 'node:crypto';
import { z } from 'zod';
import { supabase } from '@/config/supabase.js';
import { usdcToStroops } from '@/utils/payment.utils.js';
import {
  transitionPaymentStatus,
  mapProviderStatus,
  hashEventPayload,
  getPaymentByBookingId,
  appendPaymentEvent,
  derivePaymentStatus,
} from './payment.service.js';
import type { ServiceResponse } from './index.js';

// ─── Configuration ────────────────────────────────────────────────────────────

/** Maximum age of an incoming callback before it is rejected as stale. */
const MAX_CLOCK_SKEW_MS = 5 * 60 * 1_000; // 5 minutes

/** How long event IDs are retained in the replay ledger. */
const REPLAY_TTL_HOURS = 24;

// ─── Schemas ──────────────────────────────────────────────────────────────────

/**
 * Expected shape of a TrustlessWork / generic escrow callback body.
 * Unknown extra fields are stripped by Zod's .strict() equivalent via
 * passthrough — they are still hashed for the replay ledger.
 */
export const callbackBodySchema = z.object({
  /** Unique event ID issued by the provider. */
  eventId: z.string().min(1),
  /** ISO-8601 timestamp when the provider emitted this event. */
  timestamp: z.string().datetime(),
  /** Provider-specific status string — mapped via mapProviderStatus(). */
  status: z.string().min(1),
  /** UUID of the booking this event relates to. */
  bookingId: z.string().uuid(),
  /** Amount in USDC stroops (integer as string to survive JSON serialization). */
  amountStroops: z.string().regex(/^\d+$/, 'amountStroops must be a non-negative integer string'),
  /** Provider's account or API-key identifier — must match env config. */
  providerAccountId: z.string().min(1),
  /** Optional Stellar transaction hash associated with the event. */
  txHash: z.string().optional(),
}).passthrough();

export type CallbackBody = z.infer<typeof callbackBodySchema>;

// ─── Verification result ──────────────────────────────────────────────────────

export type CallbackVerificationStatus =
  | 'acknowledged'
  | 'replayed'
  | 'invalid_signature'
  | 'invalid_timestamp'
  | 'invalid_payload'
  | 'mismatch'
  | 'quarantined';

export interface CallbackVerificationResult {
  status: CallbackVerificationStatus;
  /** HTTP status code to return to the provider. */
  httpStatus: number;
  /** Safe message to surface to the provider (no internals). */
  message: string;
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

/**
 * Compute HMAC-SHA256 over `rawBody` using `secret`.
 * Returns lowercase hex.
 */
function computeHmac(rawBody: Buffer, secret: string): string {
  return createHmac('sha256', secret).update(rawBody).digest('hex');
}

/**
 * Timing-safe comparison of two hex digest strings.
 * Prevents leaking secret length via early-exit timing.
 */
function safeCompare(a: string, b: string): boolean {
  try {
    const bufA = Buffer.from(a.padEnd(64, '0').slice(0, 64), 'hex');
    const bufB = Buffer.from(b.padEnd(64, '0').slice(0, 64), 'hex');
    return timingSafeEqual(bufA, bufB) && a.length === b.length;
  } catch {
    return false;
  }
}

/**
 * Check whether `eventId` has already been processed (replay ledger).
 * Returns true when the event is a known replay.
 */
async function isReplay(eventId: string): Promise<boolean> {
  const cutoff = new Date(Date.now() - REPLAY_TTL_HOURS * 60 * 60 * 1_000).toISOString();
  const { data } = await supabase
    .from('payment_callback_events')
    .select('id')
    .eq('event_id', eventId)
    .gte('created_at', cutoff)
    .maybeSingle();
  return data !== null;
}

/**
 * Persist an event ID to the replay ledger.
 *
 * Idempotent: a duplicate insert (same event_id) is ignored via upsert so
 * concurrent deliveries of the same callback cannot create duplicate rows or
 * financial effects. Returns true when the event was newly recorded.
 */
async function recordEvent(
  eventId: string,
  bookingId: string,
  eventHash: string,
): Promise<boolean> {
  const { data, error } = await supabase
    .from('payment_callback_events')
    .upsert(
      {
        event_id: eventId,
        booking_id: bookingId,
        event_hash: eventHash,
        created_at: new Date().toISOString(),
      },
      { onConflict: 'event_id', ignoreDuplicates: true },
    )
    .select('id');

  if (error) {
    console.error(`[Callback] Failed to record replay ledger entry for eventId=${eventId}:`, error.message);
    return false;
  }
  return Array.isArray(data) && data.length > 0;
}

/**
 * Append a validated payment event to the canonical ledger.
 *
 * The ledger is append-only; the derived payment status is recomputed from
 * the stored events. Duplicate events (same idempotency key) are ignored so
 * they cannot create duplicate financial effects. Out-of-order events are
 * accepted — the derived status is order-independent.
 */
async function appendLedgerEvent(params: {
  paymentId: string;
  bookingId: string;
  providerAccountId: string;
  eventId: string;
  eventHash: string;
  canonicalStatus: string;
  amountStroops: bigint;
  txHash: string | null;
  correlationId: string;
  rawPayload: Record<string, unknown>;
}): Promise<void> {
  const result = await appendPaymentEvent({
    paymentId: params.paymentId,
    bookingId: params.bookingId,
    provider: params.providerAccountId,
    network: 'stellar',
    amountStroops: params.amountStroops,
    idempotencyKey: params.eventId,
    eventHash: params.eventHash,
    status: params.canonicalStatus,
    txHash: params.txHash,
    correlationId: params.correlationId,
    payload: params.rawPayload,
  });

  if (!result.success) {
    console.error(
      `[Callback] Failed to append ledger event for payment=${params.paymentId} ` +
      `correlationId=${params.correlationId}:`,
      result.error,
    );
  }
}

// ─── Main verifier ────────────────────────────────────────────────────────────

/**
 * Verify and process an incoming payment provider callback.
 *
 * @param rawBody          - Raw request body bytes (Buffer) for HMAC verification.
 * @param signatureHeader  - Value of the provider's signature header
 *                           (e.g. `X-TrustlessWork-Signature`).
 * @param parsedBody       - Already-parsed JSON from the request (Express req.body).
 * @param webhookSecret    - Shared HMAC secret configured in env (per-provider).
 * @param expectedProviderId - The provider account ID we expect in the payload.
 *
 * @returns CallbackVerificationResult — describes what to return to the provider.
 */
export async function verifyAndProcessCallback(
  rawBody: Buffer,
  signatureHeader: string | undefined,
  parsedBody: unknown,
  webhookSecret: string,
  expectedProviderId: string,
): Promise<CallbackVerificationResult> {

  // ── 1. Signature presence ────────────────────────────────────────────────
  if (!signatureHeader) {
    return {
      status: 'invalid_signature',
      httpStatus: 401,
      message: 'Missing signature header',
    };
  }

  // ── 2. HMAC signature verification (constant time) ───────────────────────
  const expected = computeHmac(rawBody, webhookSecret);
  if (!safeCompare(signatureHeader, expected)) {
    return {
      status: 'invalid_signature',
      httpStatus: 401,
      message: 'Signature verification failed',
    };
  }

  // ── 3. Payload schema validation ─────────────────────────────────────────
  const parseResult = callbackBodySchema.safeParse(parsedBody);
  if (!parseResult.success) {
    return {
      status: 'invalid_payload',
      httpStatus: 400,
      message: 'Malformed callback payload',
    };
  }

  const body = parseResult.data;

  // Correlation identifier threaded through every external call and log line
  // for this callback so support can trace a single delivery end-to-end.
  const correlationId = randomUUID();

  // ── 4. Clock skew check ───────────────────────────────────────────────────
  const eventAge = Date.now() - new Date(body.timestamp).getTime();
  if (Math.abs(eventAge) > MAX_CLOCK_SKEW_MS) {
    return {
      status: 'invalid_timestamp',
      httpStatus: 400,
      message: 'Event timestamp outside acceptable window',
    };
  }

  // ── 5. Provider account identity check ───────────────────────────────────
  if (body.providerAccountId !== expectedProviderId) {
    // Potential cross-tenant injection; quarantine
    console.error(
      `[Callback] Provider account mismatch correlationId=${correlationId}: ` +
      `got=${body.providerAccountId} expected=${expectedProviderId}`,
    );
    return {
      status: 'mismatch',
      httpStatus: 422,
      message: 'Provider account identity mismatch',
    };
  }

  // ── 6. Replay detection ───────────────────────────────────────────────────
  const eventHash = hashEventPayload(body as unknown as Record<string, unknown>);

  if (await isReplay(body.eventId)) {
    return {
      status: 'replayed',
      httpStatus: 200,
      message: 'Event already processed',
    };
  }

  // ── 7. Load payment and cross-reference booking + amount ─────────────────
  const payment = await getPaymentByBookingId(body.bookingId);

  if (!payment) {
    // Booking not found — could be a test event or mis-routed webhook.
    // Quarantine: record the event so support can reconcile the missing
    // provider callback against the booking, without touching financial state.
    console.warn(
      `[Callback] No payment found for bookingId=${body.bookingId} correlationId=${correlationId}`,
    );
    await recordEvent(body.eventId, body.bookingId, eventHash);
    return {
      status: 'mismatch',
      httpStatus: 422,
      message: 'Booking not found',
    };
  }

  const incomingStroops = BigInt(body.amountStroops);
  const { data: booking, error: bookingError } = await supabase
    .from('bookings')
    .select('total_price')
    .eq('id', body.bookingId)
    .single();

  if (bookingError) {
    console.error(
      `[Callback] Failed to verify booking amount for ${body.bookingId} ` +
      `correlationId=${correlationId}:`,
      bookingError.message,
    );
    return {
      status: 'quarantined',
      httpStatus: 503,
      message: 'Booking verification is temporarily unavailable; retry the event',
    };
  }

  let bookingAmountStroops: bigint | null = null;
  if (booking) {
    try {
      bookingAmountStroops = usdcToStroops(String(booking.total_price));
    } catch {
      bookingAmountStroops = null;
    }
  }

  if (
    !booking ||
    bookingAmountStroops === null ||
    incomingStroops !== payment.amount_stroops ||
    payment.amount_stroops !== bookingAmountStroops
  ) {
    // Amount mismatch — quarantine; do NOT mark paid
    console.error(
      `[Callback] Amount mismatch or booking lookup failure for bookingId=${body.bookingId} ` +
      `correlationId=${correlationId}: ` +
      `provider=${incomingStroops} payment=${payment.amount_stroops} ` +
      `booking=${bookingAmountStroops ?? 'unavailable'}`,
    );
    // Append the mismatched event to the ledger (append-only, idempotent)
    await appendLedgerEvent({
      paymentId: payment.id,
      bookingId: body.bookingId,
      providerAccountId: body.providerAccountId,
      eventId: body.eventId,
      eventHash,
      canonicalStatus: 'under_review',
      amountStroops: incomingStroops,
      txHash: body.txHash ?? null,
      correlationId,
      rawPayload: { ...body, _reason: 'amount_mismatch' } as unknown as Record<string, unknown>,
    });
    // Transition to under_review so the discrepancy is auditable
    await transitionPaymentStatus(
      payment.id,
      'under_review',
      {
        ...body,
        _reason: 'amount_mismatch',
        _correlationId: correlationId,
      } as unknown as Record<string, unknown>,
    );
    // Record in replay ledger to avoid re-processing
    await recordEvent(body.eventId, body.bookingId, eventHash);
    return {
      status: 'mismatch',
      httpStatus: 422,
      message: 'Amount mismatch — payment under review',
    };
  }

  // ── 8. Map provider status and append to the canonical ledger ─────────────
  const canonicalStatus = mapProviderStatus(body.status);

  // Append the validated event first. The ledger is append-only and idempotent
  // on eventId, so duplicate deliveries cannot create duplicate effects.
  await appendLedgerEvent({
    paymentId: payment.id,
    bookingId: body.bookingId,
    providerAccountId: body.providerAccountId,
    eventId: body.eventId,
    eventHash,
    canonicalStatus,
    amountStroops: incomingStroops,
    txHash: body.txHash ?? null,
    correlationId,
    rawPayload: body as unknown as Record<string, unknown>,
  });

  // Recompute the derived status from stored events (order-independent).
  const derived = await derivePaymentStatus(payment.id);
  if (!derived.success) {
    console.error(
      `[Callback] Failed to derive status for payment=${payment.id} correlationId=${correlationId}:`,
      derived.error,
    );
  }

  const transitionResult = await transitionPaymentStatus(
    payment.id,
    canonicalStatus,
    {
      ...body,
      _correlationId: correlationId,
    } as unknown as Record<string, unknown>,
    body.txHash ?? null,
  );

  // Record in replay ledger regardless of transition outcome
  await recordEvent(body.eventId, body.bookingId, eventHash);

  if (!transitionResult.success) {
    console.error(
      `[Callback] Transition failed for payment=${payment.id} correlationId=${correlationId}:`,
      transitionResult.error,
    );
    // Still return 200 to the provider (we received it fine; our internal
    // state diverged, which is a separate alert path).
    return {
      status: 'quarantined',
      httpStatus: 200,
      message: 'Event received; payment under review',
    };
  }

  const transition = transitionResult.data;
  if (!transition) {
    console.error(
      `[Callback] Transition returned no data for payment=${payment.id} correlationId=${correlationId}`,
    );
    return {
      status: 'quarantined',
      httpStatus: 200,
      message: 'Event received; payment under review',
    };
  }

  const { replayed } = transition;

  if (transition.payment.status === 'under_review') {
    return {
      status: 'quarantined',
      httpStatus: 200,
      message: 'Event received; payment under review',
    };
  }

  return {
    status: replayed ? 'replayed' : 'acknowledged',
    httpStatus: 200,
    message: replayed ? 'Event already processed' : 'Event acknowledged',
  };
}

// ─── HTTP handler helper ──────────────────────────────────────────────────────

/**
 * Convenience: build the provider-safe response body from a verification result.
 * Internal details are stripped.
 */
export function buildCallbackResponse(result: CallbackVerificationResult): {
  status: string;
  message: string;
} {
  return {
    status: result.status === 'acknowledged' || result.status === 'replayed'
      ? result.status
      : 'error',
    message: result.message,
  };
}

// ─── ServiceResponse wrapper ──────────────────────────────────────────────────

/**
 * Wraps verifyAndProcessCallback() to return a ServiceResponse for use in
 * controllers. Sets statusCode so the controller can call res.status().
 */
export async function processProviderCallback(
  rawBody: Buffer,
  signatureHeader: string | undefined,
  parsedBody: unknown,
  webhookSecret: string,
  expectedProviderId: string,
): Promise<ServiceResponse<CallbackVerificationResult>> {
  const result = await verifyAndProcessCallback(
    rawBody,
    signatureHeader,
    parsedBody,
    webhookSecret,
    expectedProviderId,
  );

  return {
    success: result.httpStatus < 400,
    data: result,
    statusCode: result.httpStatus,
    error: result.httpStatus >= 400 ? result.message : undefined,
  };
}

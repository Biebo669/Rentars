/**
 * Payment controller — handles USDC payment submission, status polling, retry,
 * and quote generation (#768 — amount and currency integrity).
 *
 * Amount integrity flow:
 *   1. Client requests a quote: GET /api/v1/payments/quote?bookingId=...
 *   2. Server computes the total server-side in stroops and signs it with a
 *      quote hash (HMAC-SHA256 over bookingId + amount + currency + expiry).
 *   3. Client submits the signed quote: POST /api/v1/payments/submit
 *   4. Server verifies the quote hash before creating the payment intent so
 *      the client cannot substitute a lower amount.
 *   5. On-chain settlement amounts are compared during reconciliation; any
 *      mismatch enters `under_review` without marking the booking paid.
 */

import type { Response } from 'express';
import { randomUUID } from 'node:crypto';
import { z } from 'zod';
import type { AuthRequest } from '@/middleware/auth.middleware.js';
import {
  createPaymentIntent,
  getPaymentStatus,
  updatePaymentStatus,
  getDerivedPaymentStatus,
} from '@/services/payment.service.js';
import {
  submitTransaction,
  confirmTransaction,
  retryTransaction,
  validateSignedPaymentTransaction,
} from '@/services/stellar.service.js';
import {
  validatePaymentAmount,
  usdcToStroops,
  buildAmountBreakdown,
  signQuote,
  verifyQuote,
  type SupportedCurrency,
} from '@/utils/payment.utils.js';
import { supabase } from '@/config/supabase.js';

// ─── Correlation & redaction helpers ───────────────────────────────────────────

const SENSITIVE_KEY_PATTERN =
  /(secret|token|password|passwd|private[_-]?key|seed|mnemonic|authorization|api[_-]?key|credential|xdr)/i;

/**
 * Returns a correlation id for the current request, reusing an inbound
 * `x-correlation-id` / `x-request-id` header when present so a single payment
 * flow can be traced across controller, service, and provider calls.
 */
function getCorrelationId(req: AuthRequest): string {
  const headerValue = req.headers?.['x-correlation-id'] ?? req.headers?.['x-request-id'];
  const candidate = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (typeof candidate === 'string' && candidate.trim().length > 0 && candidate.length <= 128) {
    return candidate.trim();
  }
  return randomUUID();
}

/**
 * Recursively redacts credential-like fields from a value before it is logged
 * or returned to a client. Never mutates the input.
 */
function redactCredentials<T>(value: T, depth = 0): T {
  if (depth > 8 || value === null || typeof value !== 'object') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((item) => redactCredentials(item, depth + 1)) as unknown as T;
  }
  const out: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    out[key] = SENSITIVE_KEY_PATTERN.test(key) ? '[REDACTED]' : redactCredentials(entry, depth + 1);
  }
  return out as T;
}

/**
 * Logs an error with correlation context, redacting any credential-like data
 * that may have been attached to the error object.
 */
function logPaymentError(correlationId: string, message: string, err: unknown): void {
  const detail =
    err instanceof Error
      ? { name: err.name, message: err.message, stack: err.stack }
      : redactCredentials(err);
  console.error(`[Payment][correlationId=${correlationId}] ${message}`, redactCredentials(detail));
}

// ─── Quote generation ──────────────────────────────────────────────────────────

const QUOTE_EXPIRY_MINUTES = 10;

const quoteQuerySchema = z.object({
  bookingId: z.string().uuid('bookingId must be a valid UUID'),
});

/**
 * GET /api/v1/payments/quote?bookingId=...
 *
 * Computes the payment amount server-side and returns a signed quote that the
 * client must submit back with the payment.  The quote hash binds the amount
 * to the booking so the client cannot substitute a lower value.
 *
 * Returns: { bookingId, amountStroops, amountDisplay, currency, quoteHash, expiresAt, quoteVersion }
 */
export async function getPaymentQuote(req: AuthRequest, res: Response): Promise<void> {
  const tenantId = req.userId;
  if (!tenantId) {
    res.status(401).json({ error: 'Unauthorized' });
    return;
  }

  const parsed = quoteQuerySchema.safeParse(req.query);
  if (!parsed.success) {
    res.status(400).json({ error: { code: 'VALIDATION_ERROR', details: parsed.error.flatten().fieldErrors } });
    return;
  }

  const { bookingId } = parsed.data;

  // Booking total_price is the server-computed, persisted price agreed at
  // booking time. Repricing here could change a quote after policy updates.
  const { data: booking, error } = await supabase
    .from('bookings')
    .select('id, total_price, tenant_id, status')
    .eq('id', bookingId)
    .single();

  if (error || !booking) {
    res.status(404).json({ error: 'Booking not found' });
    return;
  }

  const bookingRow = booking as {
    id: string;
    total_price: number | string;
    tenant_id: string;
    status: string;
  };

  // Verify the caller owns this booking
  if (bookingRow.tenant_id !== tenantId) {
    res.status(403).json({ error: 'Forbidden: only the booking tenant can request a quote' });
    return;
  }

  if (bookingRow.status.toLowerCase() !== 'pending') {
    res.status(409).json({ error: 'Only pending bookings can be paid' });
    return;
  }

  let amountStroops: bigint;
  try {
    amountStroops = usdcToStroops(String(bookingRow.total_price));
  } catch (err) {
    res.status(422).json({
      error: err instanceof Error ? err.message : 'Booking amount has unsupported precision',
    });
    return;
  }
  const currency: SupportedCurrency = 'USDC';

  // Generate a signed quote with expiry
  const expiresAt = new Date(Date.now() + QUOTE_EXPIRY_MINUTES * 60 * 1000).toISOString();
  const quoteHash = signQuote(bookingId, amountStroops, currency, expiresAt);

  const breakdown = buildAmountBreakdown(amountStroops, currency);

  res.json({
    bookingId,
    amountStroops: amountStroops.toString(),
    amountDisplay: breakdown.amountDisplay,
    currency,
    quoteHash,
    expiresAt,
    quoteVersion: '1',
  });
}

// ─── Payment submission ─────────────────────────────────────────────────────────

const submitSchema = z.object({
  bookingId: z.string().uuid('bookingId must be a valid UUID'),
  signedXdr: z.string().min(1, 'signedXdr is required'),
  amountStroops: z.string()
    .regex(/^\d+$/, 'amountStroops must be a non-negative integer string (stroops)'),
  currency: z.enum(['USDC']),
  quoteHash: z.string().min(1, 'quoteHash is required'),
  expiresAt: z.string().datetime('expiresAt must be an ISO-8601 datetime'),
  metadata: z.record(z.string(), z.unknown()).optional(),
});

/**
 * POST /api/v1/payments/submit
 *
 * Creates a payment intent, submits the signed XDR to Stellar, and begins
 * async confirmation polling (fire-and-forget — client polls for status).
 *
 * Body: { bookingId, signedXdr, amountStroops, currency, quoteHash, expiresAt, metadata? }
 * Returns: { paymentId, status }
 *
 * Error codes:
 *   400 VALIDATION_ERROR          — malformed request body
 *   429 PAYMENT_ATTEMPT_LIMIT_EXCEEDED — booking or actor attempt limit hit
 *   503 PAYMENT_CIRCUIT_OPEN      — provider unavailable (circuit tripped)
 *   502 TX_SUBMIT_FAILED          — Stellar submission error
 */
export async function submitPayment(req: AuthRequest, res: Response): Promise<void> {
  const parsed = submitSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { code: 'VALIDATION_ERROR', details: parsed.error.flatten().fieldErrors } });
    return;
  }

  const { bookingId, signedXdr, amountStroops, currency, quoteHash, expiresAt, metadata } = parsed.data;
  const tenantId = req.userId!;
  const correlationId = getCorrelationId(req);
  res.setHeader('x-correlation-id', correlationId);

  // ── 1. Validate amount and currency (#768) ──────────────────────────────────
  const errors = validatePaymentAmount(amountStroops, currency);
  if (errors.length > 0) {
    res.status(422).json({
      error: {
        code: 'AMOUNT_VALIDATION_FAILED',
        details: errors.map((e) => ({ field: e.field, message: e.message })),
      },
    });
    return;
  }

  const stroops = BigInt(amountStroops);
  const supportedCurrency = currency as SupportedCurrency;

  // ── 2. Verify the quote hash before creating the payment intent (#768) ──────
  // This prevents the client from substituting a lower amount.
  const quoteValid = verifyQuote(quoteHash, bookingId, stroops, supportedCurrency, expiresAt);
  if (!quoteValid) {
    res.status(422).json({
      error: {
        code: 'QUOTE_VERIFICATION_FAILED',
        message: 'The quote hash is invalid, expired, or does not match the submitted amount. Request a new quote.',
      },
    });
    return;
  }

  const { data: booking, error: bookingError } = await supabase
    .from('bookings')
    .select('id, tenant_id, total_price, status')
    .eq('id', bookingId)
    .single();

  if (bookingError || !booking) {
    res.status(404).json({ error: { code: 'BOOKING_NOT_FOUND', message: 'Booking not found' } });
    return;
  }

  if (booking.tenant_id !== tenantId) {
    res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Only the booking tenant can pay' } });
    return;
  }

  if (String(booking.status).toLowerCase() !== 'pending') {
    res.status(409).json({ error: { code: 'BOOKING_NOT_PAYABLE', message: 'Only pending bookings can be paid' } });
    return;
  }

  let bookingAmountStroops: bigint;
  try {
    bookingAmountStroops = usdcToStroops(String(booking.total_price));
  } catch (err) {
    res.status(422).json({
      error: {
        code: 'BOOKING_AMOUNT_INVALID',
        message: err instanceof Error ? err.message : 'Booking amount has unsupported precision',
      },
    });
    return;
  }

  if (stroops !== bookingAmountStroops) {
    res.status(422).json({
      error: {
        code: 'BOOKING_AMOUNT_MISMATCH',
        message: 'The quote does not match the persisted booking total. Request a new quote.',
      },
    });
    return;
  }

  try {
    validateSignedPaymentTransaction(signedXdr, stroops);
  } catch (err) {
    res.status(422).json({
      error: {
        code: 'SIGNED_TRANSACTION_MISMATCH',
        message: err instanceof Error ? err.message : 'Signed transaction does not match the payment quote',
      },
    });
    return;
  }

  // ── 3. Create payment intent in 'pending' state ─────────────────────────────
  // The idempotency key is derived from the signed quote so duplicate submits
  // of the same quote resolve to the same ledger entry.
  const idempotencyKey = quoteHash;
  const payment = await createPaymentIntent({
    bookingId,
    tenantId,
    amountStroops: stroops,
    quoteHash,
    idempotencyKey,
    correlationId,
    metadata,
  });

  // ── 4. Submit signed XDR to Stellar ─────────────────────────────────────────
  let txHash: string;
  try {
    const result = await submitTransaction(signedXdr, { correlationId, paymentId: payment.id });
    txHash = result.txHash;
    await updatePaymentStatus(payment.id, txHash, 'submitted', { correlationId });
    await recordSuccess('stellar_horizon');
  } catch (err) {
    await updatePaymentStatus(payment.id, null, 'failed', { correlationId });
    await recordFailure('stellar_horizon');
    logPaymentError(correlationId, `Transaction submission failed for payment ${payment.id}`, err);
    res.status(502).json({
      error: {
        code: 'TX_SUBMIT_FAILED',
        message: err instanceof Error ? err.message : 'Transaction submission failed',
        correlationId,
      },
    });
    return;
  }

  // ── 5. Kick off async confirmation polling (does not block the response) ───
  confirmTransaction(payment.id, txHash, { correlationId }).catch((err) => {
    logPaymentError(correlationId, `Confirmation polling failed for payment ${payment.id}`, err);
  });

  res.status(202).json({
    paymentId: payment.id,
    status: 'submitted',
    txHash,
    correlationId,
    idempotencyKey,
  });
}

// ─── Status polling ────────────────────────────────────────────────────────────

/**
 * GET /api/v1/payments/:id/status
 *
 * Returns the current payment status, tx hash, and amount breakdown.
 * Frontend polls this every 3 seconds while status is 'submitted'.
 */
export async function getStatus(req: AuthRequest, res: Response): Promise<void> {
  const id = req.params.id;
  if (typeof id !== 'string' || !id.trim()) {
    res.status(400).json({ error: { code: 'INVALID_PAYMENT_ID', message: 'Payment ID is required' } });
    return;
  }
  const payment = await getPaymentStatus(id);

  if (!payment) {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Payment not found' } });
    return;
  }

  // Only the owning tenant or an admin may query
  if (payment.tenant_id !== req.userId && req.user?.role !== 'admin') {
    res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Access denied' } });
    return;
  }

  const breakdown = buildAmountBreakdown(payment.amount_stroops, payment.currency);

  // The derived status is reproducible from the stored payment events; fall
  // back to the persisted status only if the ledger cannot be read.
  let derivedStatus = payment.status;
  try {
    const derived = await getDerivedPaymentStatus(payment.id);
    if (derived) derivedStatus = derived;
  } catch (err) {
    logPaymentError(getCorrelationId(req), `Failed to derive ledger status for payment ${payment.id}`, err);
  }

  res.json({
    paymentId: payment.id,
    bookingId: payment.booking_id,
    status: derivedStatus,
    persistedStatus: payment.status,
    txHash: payment.stellar_tx_hash,
    amountStroops: payment.amount_stroops.toString(),
    amountDisplay: breakdown.amountDisplay,
    currency: payment.currency,
    updatedAt: payment.updated_at,
  });
}

// ─── Retry ─────────────────────────────────────────────────────────────────────

const retrySchema = z.object({
  signedXdr: z.string().optional(),
});

/**
 * POST /api/v1/payments/:id/retry
 *
 * Retries a failed or timed-out payment safely.
 * If the payment already has a txHash, it re-polls instead of re-submitting.
 *
 * Retries count against the attempt limits and are subject to circuit
 * breaker checks exactly like original submissions.
 *
 * Body: { signedXdr? } — only required if no txHash exists on the payment.
 *
 * Error codes:
 *   400 VALIDATION_ERROR          — malformed request body
 *   404 NOT_FOUND                 — payment not found
 *   403 FORBIDDEN                 — caller is not the owning tenant
 *   429 PAYMENT_ATTEMPT_LIMIT_EXCEEDED — attempt limit hit
 *   503 PAYMENT_CIRCUIT_OPEN      — provider unavailable
 *   422 RETRY_FAILED              — retry logic failed
 */
export async function retryPayment(req: AuthRequest, res: Response): Promise<void> {
  const id = req.params.id;
  if (typeof id !== 'string' || !id.trim()) {
    res.status(400).json({ error: { code: 'INVALID_PAYMENT_ID', message: 'Payment ID is required' } });
    return;
  }

  const parsed = retrySchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: { code: 'VALIDATION_ERROR', details: parsed.error.flatten().fieldErrors } });
    return;
  }

  const payment = await getPaymentStatus(id);
  if (!payment) {
    res.status(404).json({ error: { code: 'NOT_FOUND', message: 'Payment not found' } });
    return;
  }

  if (payment.tenant_id !== req.userId) {
    res.status(403).json({ error: { code: 'FORBIDDEN', message: 'Access denied' } });
    return;
  }

  const tenantId = req.userId!;
  const correlationId = getCorrelationId(req);
  res.setHeader('x-correlation-id', correlationId);

  // ── Attempt limiter ────────────────────────────────────────────────────────
  const attemptResult = await checkAndIncrementAttempts(payment.booking_id, tenantId);
  if (!attemptResult.allowed) {
    res.status(429).json({
      error: {
        code: 'PAYMENT_ATTEMPT_LIMIT_EXCEEDED',
        message: 'Too many payment attempts. Please try again later.',
        retryAfterSeconds: attemptResult.retryAfterSeconds ?? 3600,
      },
    });
    return;
  }

  // ── Circuit breaker ────────────────────────────────────────────────────────
  try {
    await checkCircuit('stellar_horizon');
  } catch (err) {
    if (err instanceof PaymentCircuitOpenError) {
      res.status(503).json({
        error: {
          code: 'PAYMENT_CIRCUIT_OPEN',
          message: 'Payment processing is temporarily unavailable. Please try again in a few minutes.',
          retryAfterSeconds: Math.ceil(err.retryAfterMs / 1000),
        },
      });
      return;
    }
    throw err;
  }

  try {
    const result = await retryTransaction(id, parsed.data.signedXdr, { correlationId });
    res.json({
      paymentId: id,
      txHash: result.txHash,
      status: result.status,
      correlationId,
    });
  } catch (err) {
    logPaymentError(correlationId, `Retry failed for payment ${id}`, err);
    res.status(422).json({
      error: {
        code: 'RETRY_FAILED',
        message: err instanceof Error ? err.message : 'Retry failed',
        correlationId,
      },
    });
  }
}

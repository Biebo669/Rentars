const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000';

export interface BlockchainStatus {
  verified: boolean;
  hash: string | null;
  lastVerified: string | null;
  pending: boolean;
  failed?: boolean;
  failureReason?: string | null;
}

export async function verifyProperty(propertyId: string): Promise<BlockchainStatus> {
  const response = await fetch(`${API_URL}/api/properties/${propertyId}/verify`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });

  if (!response.ok) {
    throw new Error('Failed to verify property');
  }

  return response.json();
}

export async function getBlockchainStatus(propertyId: string): Promise<BlockchainStatus> {
  const response = await fetch(`${API_URL}/api/properties/${propertyId}/blockchain-status`);

  if (!response.ok) {
    throw new Error('Failed to fetch blockchain status');
  }

  return response.json();
}

/**
 * Payment finality status, distinct from booking creation.
 * A booking can exist (created) while its payment is still pending or has failed.
 */
export type PaymentStatus = 'pending' | 'confirmed' | 'failed' | 'unknown';

export type EscrowStatus = 'pending' | 'secured' | 'released' | 'refunded' | 'failed' | 'unknown';

export interface BookingConfirmation {
  bookingId: string;
  propertyId: string;
  /** Whether the booking record itself was successfully created. */
  bookingCreated: boolean;
  /** Payment finality — separate from booking creation. */
  paymentStatus: PaymentStatus;
  /** Escrow state — only reported as secured/released when verified server-side. */
  escrowStatus: EscrowStatus;
  /** Transaction hash associated with the payment, if any. */
  transactionHash: string | null;
  /** Whether the chain transaction is still awaiting confirmation. */
  transactionPending: boolean;
  /** Human-readable reason when payment or escrow failed. */
  failureReason: string | null;
  /** Timestamp of the last server verification. */
  lastVerified: string | null;
}

export type ConfirmationLoadResult =
  | { state: 'ok'; data: BookingConfirmation }
  | { state: 'not-found' }
  | { state: 'unauthorized' }
  | { state: 'error'; message: string };

const BOOKING_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;

export function isValidBookingId(bookingId: string | null | undefined): bookingId is string {
  return typeof bookingId === 'string' && BOOKING_ID_PATTERN.test(bookingId);
}

/**
 * Server-backed loader for booking confirmation state.
 * Validates the identifier and maps HTTP responses to typed states so that
 * invalid or inaccessible bookings surface the standard not-found/unauthorized
 * responses rather than a misleading confirmation.
 */
export async function loadBookingConfirmation(
  bookingId: string | null | undefined,
): Promise<ConfirmationLoadResult> {
  if (!isValidBookingId(bookingId)) {
    return { state: 'not-found' };
  }

  let response: Response;
  try {
    response = await fetch(`${API_URL}/api/bookings/${encodeURIComponent(bookingId)}/confirmation`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
      cache: 'no-store',
    });
  } catch (err) {
    return {
      state: 'error',
      message: err instanceof Error ? err.message : 'Failed to load booking confirmation',
    };
  }

  if (response.status === 404) {
    return { state: 'not-found' };
  }

  if (response.status === 401 || response.status === 403) {
    return { state: 'unauthorized' };
  }

  if (!response.ok) {
    return { state: 'error', message: 'Failed to load booking confirmation' };
  }

  let payload: Partial<BookingConfirmation>;
  try {
    payload = (await response.json()) as Partial<BookingConfirmation>;
  } catch {
    return { state: 'error', message: 'Invalid confirmation response' };
  }

  const paymentStatus: PaymentStatus =
    payload.paymentStatus === 'pending' ||
    payload.paymentStatus === 'confirmed' ||
    payload.paymentStatus === 'failed'
      ? payload.paymentStatus
      : 'unknown';

  const escrowStatus: EscrowStatus =
    payload.escrowStatus === 'pending' ||
    payload.escrowStatus === 'secured' ||
    payload.escrowStatus === 'released' ||
    payload.escrowStatus === 'refunded' ||
    payload.escrowStatus === 'failed'
      ? payload.escrowStatus
      : 'unknown';

  return {
    state: 'ok',
    data: {
      bookingId: typeof payload.bookingId === 'string' ? payload.bookingId : bookingId,
      propertyId: typeof payload.propertyId === 'string' ? payload.propertyId : '',
      bookingCreated: payload.bookingCreated === true,
      paymentStatus,
      escrowStatus,
      transactionHash: typeof payload.transactionHash === 'string' ? payload.transactionHash : null,
      transactionPending: payload.transactionPending === true,
      failureReason: typeof payload.failureReason === 'string' ? payload.failureReason : null,
      lastVerified: typeof payload.lastVerified === 'string' ? payload.lastVerified : null,
    },
  };
}

export interface PollOptions {
  /** Maximum number of attempts before giving up. */
  maxAttempts?: number;
  /** Initial delay in milliseconds. */
  initialDelayMs?: number;
  /** Maximum delay in milliseconds (caps exponential backoff). */
  maxDelayMs?: number;
  /** Backoff multiplier. */
  factor?: number;
  /** Optional abort signal to cancel polling. */
  signal?: AbortSignal;
}

const DEFAULT_POLL_OPTIONS: Required<Omit<PollOptions, 'signal'>> = {
  maxAttempts: 8,
  initialDelayMs: 1000,
  maxDelayMs: 15000,
  factor: 1.6,
};

function delay(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(new DOMException('Aborted', 'AbortError'));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(new DOMException('Aborted', 'AbortError'));
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/**
 * Polls the confirmation endpoint only while the transaction is pending,
 * using bounded exponential backoff. Stops as soon as the transaction is no
 * longer pending, the booking is not found/unauthorized, or attempts are
 * exhausted. Never reports escrow as secured/released unless the server does.
 */
export async function pollBookingConfirmation(
  bookingId: string,
  options: PollOptions = {},
): Promise<ConfirmationLoadResult> {
  const { maxAttempts, initialDelayMs, maxDelayMs, factor } = {
    ...DEFAULT_POLL_OPTIONS,
    ...options,
  };
  const { signal } = options;

  let lastResult: ConfirmationLoadResult = { state: 'error', message: 'No confirmation attempt made' };
  let wait = initialDelayMs;

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    if (signal?.aborted) {
      throw new DOMException('Aborted', 'AbortError');
    }

    lastResult = await loadBookingConfirmation(bookingId);

    if (lastResult.state !== 'ok') {
      return lastResult;
    }

    const { transactionPending, paymentStatus } = lastResult.data;
    if (!transactionPending && paymentStatus !== 'pending') {
      return lastResult;
    }

    if (attempt < maxAttempts - 1) {
      await delay(wait, signal);
      wait = Math.min(Math.round(wait * factor), maxDelayMs);
    }
  }

  return lastResult;
}
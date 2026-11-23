// ─── Booking status ───────────────────────────────────────────────────────────

/**
 * All valid booking status values.
 *
 * DB stores title-case (Pending, Confirmed, …) but the frontend normalises
 * everything to lowercase for comparisons so both forms are included.
 */
export type BookingStatus =
  | 'Pending'   | 'pending'
  | 'Confirmed' | 'confirmed'
  | 'Completed' | 'completed'
  | 'Cancelled' | 'cancelled'
  | 'Disputed'  | 'disputed'
  | 'escrow_reconcile_failed';

/** Normalise a raw status string from the API to lowercase. */
export function normaliseStatus(status: string): Lowercase<BookingStatus> {
  return status.toLowerCase() as Lowercase<BookingStatus>;
}

// ─── Allowed lifecycle transitions ───────────────────────────────────────────

/**
 * Valid transitions the current user (tenant) may trigger from each state.
 * Mirrors the server-side state machine.
 */
export const TENANT_TRANSITIONS: Record<string, ('confirm' | 'complete' | 'cancel' | 'dispute')[]> = {
  pending:   ['cancel'],
  confirmed: ['complete', 'dispute', 'cancel'],
  completed: [],
  cancelled: [],
  disputed:  [],
};

// ─── Shared booking action matrix ────────────────────────────────────────────

/** The party viewing a booking. */
export type BookingRole = 'tenant' | 'host';

/** Lifecycle actions that can be presented for a booking. */
export type BookingAction = 'confirm' | 'complete' | 'cancel' | 'dispute';

/** Normalised payment/escrow state used by the presentation policy. */
export type BookingPaymentState =
  | 'none'
  | 'pending'
  | 'locked'
  | 'released'
  | 'refunded'
  | 'manual_review';

/** Normalised booking status used as a matrix key. */
export type NormalisedBookingStatus = Lowercase<BookingStatus>;

/** Result of evaluating the action matrix for a single action. */
export interface BookingActionAvailability {
  action: BookingAction;
  allowed: boolean;
  /** Human-readable explanation when the action is not allowed. */
  reason?: string;
}

/** Full presentation policy for a booking, for a given role. */
export interface BookingActionPolicy {
  role: BookingRole;
  status: NormalisedBookingStatus;
  paymentState: BookingPaymentState;
  /** Actions the UI may present, in display order. */
  allowed: BookingAction[];
  /** Actions that exist for this state but are unavailable, with reasons. */
  unavailable: BookingActionAvailability[];
}

/** Normalise a raw escrow/payment status to a known payment state. */
export function normalisePaymentState(
  escrowStatus?: Booking['escrow_status'] | string | null,
): BookingPaymentState {
  switch ((escrowStatus ?? '').toLowerCase()) {
    case 'locked':
      return 'locked';
    case 'released':
      return 'released';
    case 'refunded':
      return 'refunded';
    case 'pending':
      return 'pending';
    case 'manual_review':
      return 'manual_review';
    default:
      return 'none';
  }
}

const ALL_ACTIONS: BookingAction[] = ['confirm', 'complete', 'cancel', 'dispute'];

/**
 * Base matrix: which actions are structurally valid for each role/status.
 * This mirrors the backend state machine but is presentation-only — the
 * backend remains authoritative for authorization.
 */
const ACTION_MATRIX: Record<BookingRole, Partial<Record<NormalisedBookingStatus, BookingAction[]>>> = {
  tenant: {
    pending: ['cancel'],
    confirmed: ['complete', 'dispute', 'cancel'],
    completed: [],
    cancelled: [],
    disputed: [],
    escrow_reconcile_failed: [],
  },
  host: {
    pending: ['confirm', 'cancel'],
    confirmed: ['complete', 'cancel'],
    completed: [],
    cancelled: [],
    disputed: [],
    escrow_reconcile_failed: [],
  },
};

/** Payment-state constraints applied on top of the base matrix. */
function paymentBlockReason(
  action: BookingAction,
  paymentState: BookingPaymentState,
): string | undefined {
  if (paymentState === 'manual_review') {
    return 'Payment is under manual review. Actions are temporarily unavailable.';
  }
  if (action === 'complete' && paymentState !== 'locked') {
    return 'Completion requires funds to be held in escrow.';
  }
  if (action === 'dispute' && paymentState === 'refunded') {
    return 'This booking has already been refunded and cannot be disputed.';
  }
  return undefined;
}

/** Status-level explanation for an action that is not valid in this state. */
function statusBlockReason(
  action: BookingAction,
  status: NormalisedBookingStatus,
): string {
  switch (status) {
    case 'completed':
      return 'This booking is already completed.';
    case 'cancelled':
      return 'This booking has been cancelled.';
    case 'disputed':
      return 'This booking is in dispute and is awaiting resolution.';
    case 'escrow_reconcile_failed':
      return 'Escrow reconciliation failed. Contact support before taking action.';
    default:
      return `The "${action}" action is not available for this booking.`;
  }
}

/**
 * Evaluate the shared action matrix for a booking from the perspective of
 * the given role. Derived purely from server-loaded booking state; the
 * backend still enforces authorization on every mutation.
 */
export function getBookingActionPolicy(
  booking: Pick<Booking, 'status' | 'escrow_status'>,
  role: BookingRole,
): BookingActionPolicy {
  const status = normaliseStatus(booking.status);
  const paymentState = normalisePaymentState(booking.escrow_status);
  const structurallyAllowed = ACTION_MATRIX[role][status] ?? [];

  const allowed: BookingAction[] = [];
  const unavailable: BookingActionAvailability[] = [];

  for (const action of ALL_ACTIONS) {
    if (!structurallyAllowed.includes(action)) {
      unavailable.push({
        action,
        allowed: false,
        reason: statusBlockReason(action, status),
      });
      continue;
    }

    const blockReason = paymentBlockReason(action, paymentState);
    if (blockReason) {
      unavailable.push({ action, allowed: false, reason: blockReason });
    } else {
      allowed.push(action);
    }
  }

  return { role, status, paymentState, allowed, unavailable };
}

/** Convenience helper: the list of actions the UI may present. */
export function getAllowedBookingActions(
  booking: Pick<Booking, 'status' | 'escrow_status'>,
  role: BookingRole,
): BookingAction[] {
  return getBookingActionPolicy(booking, role).allowed;
}

/** Convenience helper: explanatory reason for a single action, if blocked. */
export function getBookingActionUnavailableReason(
  booking: Pick<Booking, 'status' | 'escrow_status'>,
  role: BookingRole,
  action: BookingAction,
): string | undefined {
  return getBookingActionPolicy(booking, role).unavailable.find(
    (entry) => entry.action === action,
  )?.reason;
}

// ─── Core types ───────────────────────────────────────────────────────────────

export interface Booking {
  id: string;
  property_id: string;
  tenant_id: string;
  check_in: string;
  check_out: string;
  guest_count: number;
  total_price: number;
  status: BookingStatus;
  escrow_id?: string;
  escrow_status?: 'locked' | 'released' | 'refunded' | 'pending' | 'manual_review';
  on_chain_id?: number;
  rules_acknowledged_at?: string | null;
  dispute_reason?: string | null;
  created_at: string;
  updated_at?: string;
}

export interface BookingFormData {
  checkIn: Date;
  checkOut: Date;
  guestCount: number;
  propertyId: string;
}

export interface BookingWithProperty extends Booking {
  property?: {
    id: string;
    title: string;
    city?: string;
    country?: string;
    address?: string;
    images?: string[];
    slug?: string;
    owner_id?: string;
  };
}

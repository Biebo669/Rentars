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

// ─── Dispute timeline (participant-safe read model) ──────────────────────────

/**
 * Lifecycle stages of a dispute as exposed to participants.
 *
 * A recorded decision is deliberately distinct from the financial settlement
 * that follows it: a refund or release may still be pending (or may fail)
 * after the decision has been recorded.
 */
export type DisputeTimelineStage =
  | 'opened'
  | 'under_review'
  | 'decision_recorded'
  | 'settlement_pending'
  | 'settlement_completed'
  | 'settlement_failed';

/** Financial action that a dispute decision may trigger. */
export type DisputeFinancialAction = 'refund' | 'release' | 'none';

/** Verified state of the financial action, sourced from the payment ledger. */
export type DisputeSettlementStatus =
  | 'not_required'
  | 'pending'
  | 'completed'
  | 'failed';

/** A single entry in the participant-safe dispute timeline. */
export interface DisputeTimelineEvent {
  id: string;
  stage: DisputeTimelineStage;
  /** ISO timestamp of when this transition occurred. */
  occurred_at: string;
  /** Participant-facing summary. Never contains internal evidence or reviewer notes. */
  message?: string | null;
  /** Financial action associated with this event, if any. */
  financial_action?: DisputeFinancialAction;
  /** Verified settlement status at the time of this event. */
  settlement_status?: DisputeSettlementStatus;
}

/**
 * Aggregated dispute timeline for a booking.
 *
 * `decision_recorded` reflects that a decision exists; it does NOT imply the
 * refund/release has completed. Consumers must check `settlement_status`
 * (and `settlement_completed_at`) before presenting the dispute as resolved.
 */
export interface DisputeTimeline {
  booking_id: string;
  dispute_id?: string;
  /** Current authoritative stage, derived from decision history + payment state. */
  current_stage: DisputeTimelineStage;
  /** Whether a decision has been recorded (independent of settlement). */
  decision_recorded: boolean;
  /** ISO timestamp of the recorded decision, if any. */
  decision_recorded_at?: string | null;
  /** Financial action resulting from the decision, if any. */
  financial_action: DisputeFinancialAction;
  /** Verified settlement state from the payment ledger. */
  settlement_status: DisputeSettlementStatus;
  /** ISO timestamp when settlement was verified complete, if applicable. */
  settlement_completed_at?: string | null;
  /** ISO timestamp of the last settlement attempt (successful or not). */
  settlement_last_attempt_at?: string | null;
  /** Participant-safe failure reason when settlement_status is 'failed'. */
  settlement_failure_reason?: string | null;
  /** Ordered events, oldest first. */
  events: DisputeTimelineEvent[];
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

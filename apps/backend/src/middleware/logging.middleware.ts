import { randomUUID } from 'node:crypto';
import { type Request, type Response, type NextFunction } from 'express';
import { env } from '../config/env.js';
import { getRequestContext, runWithRequestContext } from '../services/logging.service.js';
import { redactLogFields, redactRequestHeaders } from '../utils/redact.js';

// ── Log levels ────────────────────────────────────────────────────────────────

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_PRIORITY: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

function getConfiguredLevel(): LogLevel {
  const raw = (process.env.LOG_LEVEL ?? 'info').toLowerCase();
  if (raw in LEVEL_PRIORITY) return raw as LogLevel;
  return 'info';
}

// ── Structured logger ─────────────────────────────────────────────────────────

export interface LogEntry {
  level: LogLevel;
  message: string;
  timestamp: string;
  requestId?: string;
  userId?: string;
  [key: string]: unknown;
}

/**
 * Well-known top-level schema keys that are safe to include verbatim.
 * Every other key on a LogEntry is treated as an "extra" and passed through
 * redactLogFields before serialisation so that a caller who accidentally
 * includes a request body, provider response, or auth object cannot leak
 * credentials into the log-aggregation pipeline.
 */
const SAFE_SCHEMA_KEYS = new Set([
  'level', 'message', 'timestamp', 'requestId', 'userId',
  'method', 'path', 'status', 'durationMs', 'ip',
  'userAgent', 'route',
]);

/**
 * Emit a structured JSON log line.
 *
 * In development the line is pretty-printed; in production it is a single-line
 * JSON object suitable for log-aggregation pipelines (Loki, CloudWatch, etc.).
 *
 * The log is suppressed when its level falls below the configured LOG_LEVEL.
 *
 * Before serialisation any field that is not in SAFE_SCHEMA_KEYS is passed
 * through redactLogFields, ensuring credentials and PII in arbitrary extra
 * fields are stripped before they reach the log sink.
 */
export function structuredLog(entry: LogEntry): void {
  const configuredLevel = getConfiguredLevel();
  if (LEVEL_PRIORITY[entry.level] < LEVEL_PRIORITY[configuredLevel]) return;

  // Fall back to the AsyncLocalStorage-backed request context for any field
  // the caller didn't set explicitly.
  const context = getRequestContext();

  // Separate safe schema keys from arbitrary extras.
  const safeFields: Record<string, unknown> = {};
  const extraFields: Record<string, unknown> = {};

  for (const [k, v] of Object.entries(entry)) {
    if (SAFE_SCHEMA_KEYS.has(k)) {
      safeFields[k] = v;
    } else {
      extraFields[k] = v;
    }
  }

  // Redact extras in-place before merging into the final log line.
  const redactedExtras = redactLogFields(extraFields) as Record<string, unknown>;

  const merged: LogEntry = {
    ...(safeFields as LogEntry),
    requestId: (safeFields.requestId as string | undefined) ?? context?.requestId,
    userId: (safeFields.userId as string | undefined) ?? context?.userId,
    ...redactedExtras,
  };

  const line =
    env.NODE_ENV === 'development'
      ? JSON.stringify(merged, null, 2)
      : JSON.stringify(merged);

  if (merged.level === 'error') {
    console.error(line);
  } else if (merged.level === 'warn') {
    console.warn(line);
  } else {
    console.log(line);
  }
}

// ── Request-ID injection ──────────────────────────────────────────────────────

/**
 * Attach a unique request-ID to every incoming request so that all log
 * entries emitted during that request can be correlated in a dashboard.
 *
 * The ID is read from the `X-Request-Id` header if the upstream proxy
 * already set one; otherwise a fresh UUID v4 is generated.
 * The final ID is echoed back to the caller in `X-Request-Id`.
 */
export function requestIdMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  const incomingId = req.headers['x-request-id'];
  const requestId =
    typeof incomingId === 'string' && incomingId.length > 0
      ? incomingId
      : randomUUID();

  (req as RequestWithId).requestId = requestId;
  res.setHeader('X-Request-Id', requestId);

  runWithRequestContext({ requestId, method: req.method, path: req.path }, next);
}

// ── Typed request extension ───────────────────────────────────────────────────

export interface RequestWithId extends Request {
  requestId?: string;
  userId?: string;
}

// ── HTTP request logging middleware ──────────────────────────────────────────

/**
 * Structured HTTP request/response logger.
 *
 * Emits one structured log entry per request on response finish. The
 * `userAgent` and all request headers beyond the safe set are run through
 * redactRequestHeaders so that Authorization or Cookie values set by an
 * upstream proxy cannot appear in the access log.
 *
 * Fields logged (all safe — no body, no raw headers):
 *   timestamp, requestId, userId, method, path, status, durationMs, ip,
 *   userAgent (from safe-header allowlist)
 */
const SKIP_PATHS = new Set(['/health', '/metrics', '/favicon.ico']);

export function requestLoggingMiddleware(
  req: Request,
  res: Response,
  next: NextFunction,
): void {
  if (SKIP_PATHS.has(req.path)) {
    next();
    return;
  }

  const startMs = Date.now();
  const typedReq = req as RequestWithId;

  res.on('finish', () => {
    const duration = Date.now() - startMs;
    const level: LogLevel =
      res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'info';

    // Redact request headers so Authorization / Cookie can never appear in
    // the access log even if they were forwarded by a misconfigured proxy.
    const safeHeaders = redactRequestHeaders(
      req.headers as Record<string, string | string[] | undefined>,
    );

    structuredLog({
      level,
      message: `${req.method} ${req.path} ${res.statusCode}`,
      timestamp: new Date().toISOString(),
      requestId: typedReq.requestId,
      userId: typedReq.userId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      durationMs: duration,
      // userAgent sourced from the already-redacted header map (safe field)
      userAgent: safeHeaders['user-agent'] as string | undefined,
      ip: req.ip,
    });
  });

  next();
}

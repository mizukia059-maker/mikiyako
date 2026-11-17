import crypto from 'crypto';

export const USERNAME_REGEX = /^[a-zA-Z0-9_.-]{3,20}$/;

export const RESERVED_USERNAMES = [
  'ceo_miki',
  'ceo_yako',
  'ceo miki',
  'ceo yako',
  'miki',
  'yako',
  'admin',
  'administrador',
  'administracion',
  'ymki'
];

export interface PasswordCred {
  salt: string;
  hash: string;
  isFounder?: boolean;
  lastLogin?: string;
}

export interface RateLimitEntry {
  count: number;
  windowStart?: number;
  lockedUntil?: number;
}

export interface RecoveryTokenRecord {
  codeHash: string;
  expiresAt: number;
  issuedBy?: string;
  createdAt?: number;
}

export interface ActiveSession {
  token: string;
  username: string;
  createdAt: number;
  expiresAt: number;
  ip?: string;
}

export function hashPassword(password: string, salt?: string): { salt: string; hash: string } {
  const actualSalt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, actualSalt, 64).toString('hex');
  return { salt: actualSalt, hash };
}

export function verifyPassword(password: string, salt: string, storedHash: string): boolean {
  try {
    const hash = crypto.scryptSync(password, salt, 64).toString('hex');
    const a = Buffer.from(hash, 'hex');
    const b = Buffer.from(storedHash, 'hex');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

export function isValidUsername(username: string): boolean {
  return USERNAME_REGEX.test(username.trim());
}

export function isReservedUsername(username: string): boolean {
  return RESERVED_USERNAMES.includes(username.trim().toLowerCase());
}

export function shouldAssignFirstServerAdmin(
  allProfiles: Record<string, any> | undefined,
  firstRegisteredUser?: string
): boolean {
  const profiles = allProfiles && typeof allProfiles === 'object' ? allProfiles : {};
  const keys = Object.keys(profiles);
  if (keys.length === 0) return true;

  const hasValidFirstUser = Boolean(
    firstRegisteredUser &&
      keys.some((k) => k.toLowerCase() === firstRegisteredUser.trim().toLowerCase())
  );
  const hasAnyAdminOrFounder = Object.values(profiles).some((p: any) =>
    Boolean(p && (p.isFounder === true || p.accountType === 'admin'))
  );

  return !hasValidFirstUser && !hasAnyAdminOrFounder;
}

export function buildRateLimitKey(ip: string | undefined, identifier: string): string {
  const safeIp = (ip || 'unknown').trim().toLowerCase();
  const safeId = (identifier || '').trim().toLowerCase().replace(/\s+/g, '');
  return `${safeIp}:${safeId}`;
}

export const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000;
export const RATE_LIMIT_LOCK_MS = 2 * 60 * 1000;
export const RATE_LIMIT_MAX_ATTEMPTS = 6;

export function checkRateLimitStatus(
  attempts: Record<string, RateLimitEntry>,
  key: string,
  nowMs: number = Date.now()
): { allowed: boolean; retryAfterMs: number } {
  const entry = attempts[key];
  if (!entry) return { allowed: true, retryAfterMs: 0 };

  if (entry.lockedUntil && entry.lockedUntil > nowMs) {
    return { allowed: false, retryAfterMs: entry.lockedUntil - nowMs };
  }

  // Lock expired or window expired -> reset clean state
  if (
    (entry.lockedUntil && entry.lockedUntil <= nowMs) ||
    (entry.windowStart && nowMs - entry.windowStart > RATE_LIMIT_WINDOW_MS)
  ) {
    delete attempts[key];
    return { allowed: true, retryAfterMs: 0 };
  }

  return { allowed: true, retryAfterMs: 0 };
}

export function recordFailedRateLimitAttempt(
  attempts: Record<string, RateLimitEntry>,
  key: string,
  nowMs: number = Date.now()
): RateLimitEntry {
  const existing = attempts[key];
  if (
    !existing ||
    (existing.lockedUntil && existing.lockedUntil <= nowMs) ||
    (existing.windowStart && nowMs - existing.windowStart > RATE_LIMIT_WINDOW_MS)
  ) {
    const fresh: RateLimitEntry = { count: 1, windowStart: nowMs };
    attempts[key] = fresh;
    return fresh;
  }

  existing.count += 1;
  if (existing.count >= RATE_LIMIT_MAX_ATTEMPTS) {
    existing.lockedUntil = nowMs + RATE_LIMIT_LOCK_MS;
  }
  return existing;
}

export function clearRateLimitAttempt(attempts: Record<string, RateLimitEntry>, key: string): void {
  delete attempts[key];
}

export interface SuspensionStatus {
  suspended: boolean;
  expired: boolean;
  reason?: string;
  expires?: string;
}

export function evaluateSuspension(
  profile: any,
  nowMs: number = Date.now()
): SuspensionStatus {
  if (!profile || !profile.isSuspended) {
    return { suspended: false, expired: false };
  }

  const exp = profile.suspensionExpires;
  if (!exp || String(exp).toLowerCase() === 'permanente') {
    return {
      suspended: true,
      expired: false,
      reason: profile.suspensionReason || 'Cuenta suspendida permanentemente.',
      expires: 'permanente'
    };
  }

  const parsed = new Date(exp).getTime();
  if (Number.isNaN(parsed) || parsed > nowMs) {
    return {
      suspended: true,
      expired: false,
      reason: profile.suspensionReason || 'Cuenta temporalmente suspendida.',
      expires: String(exp)
    };
  }

  return { suspended: false, expired: true };
}

export function clearExpiredSuspension(profile: any, penaltiesHistory?: any[], username?: string): void {
  if (!profile) return;
  profile.isSuspended = false;
  delete profile.suspensionReason;
  delete profile.suspensionExpires;

  if (Array.isArray(penaltiesHistory) && username) {
    const uLower = username.toLowerCase();
    for (const pen of penaltiesHistory) {
      if (
        pen &&
        typeof pen.targetUsername === 'string' &&
        pen.targetUsername.toLowerCase() === uLower &&
        pen.status === 'activa' &&
        (pen.type === 'temp_ban' || pen.type === 'suspend_user') &&
        pen.expiresAt &&
        new Date(pen.expiresAt).getTime() <= Date.now()
      ) {
        pen.status = 'expirada';
      }
    }
  }
}

export function createRecoveryTokenRecord(
  nowMs: number = Date.now(),
  ttlMs: number = 15 * 60 * 1000,
  issuedBy?: string
): { rawToken: string; record: RecoveryTokenRecord } {
  const rawToken = crypto.randomBytes(16).toString('hex');
  const codeHash = crypto.createHash('sha256').update(rawToken).digest('hex');
  return {
    rawToken,
    record: {
      codeHash,
      expiresAt: nowMs + ttlMs,
      issuedBy,
      createdAt: nowMs
    }
  };
}

export function verifyRecoveryToken(
  record: RecoveryTokenRecord | undefined,
  providedToken: string,
  nowMs: number = Date.now()
): boolean {
  if (!record || !record.codeHash || !providedToken) return false;
  if (record.expiresAt <= nowMs) return false;
  const providedHash = crypto.createHash('sha256').update(String(providedToken).trim()).digest('hex');
  const a = Buffer.from(providedHash, 'hex');
  const b = Buffer.from(record.codeHash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function revokeUserSessions(
  activeSessions: Record<string, ActiveSession> | undefined,
  username: string,
  keepToken?: string
): number {
  if (!activeSessions) return 0;
  const uLower = username.toLowerCase();
  let removed = 0;
  for (const [token, sess] of Object.entries(activeSessions)) {
    if (sess?.username?.toLowerCase() === uLower && (!keepToken || token !== keepToken)) {
      delete activeSessions[token];
      removed += 1;
    }
  }
  return removed;
}

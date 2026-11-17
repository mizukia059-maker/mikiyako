import test from 'node:test';
import assert from 'node:assert/strict';
import {
  hashPassword,
  verifyPassword,
  isValidUsername,
  buildRateLimitKey,
  checkRateLimitStatus,
  recordFailedRateLimitAttempt,
  evaluateSuspension,
  createRecoveryTokenRecord,
  verifyRecoveryToken,
  revokeUserSessions,
  shouldAssignFirstServerAdmin
} from './authSecurity';

test('hashPassword and verifyPassword support scrypt verification with timingSafeEqual', () => {
  const { salt, hash } = hashPassword('SuperSecret!23');
  assert.equal(verifyPassword('SuperSecret!23', salt, hash), true);
  assert.equal(verifyPassword('WrongPass', salt, hash), false);
});

test('isValidUsername allows dots, underscores, hyphens and alphanumeric 3..20 chars', () => {
  assert.equal(isValidUsername('aurora.fan_1'), true);
  assert.equal(isValidUsername('ab'), false);
  assert.equal(isValidUsername('user with space'), false);
});

test('rate limiting locks after 6 failures and cleanly resets after lock expiry', () => {
  const attempts: Record<string, any> = {};
  const key = buildRateLimitKey('127.0.0.1', ' TestFan ');
  let t = 1_000_000;

  for (let i = 0; i < 6; i++) {
    recordFailedRateLimitAttempt(attempts, key, t);
  }
  const locked = checkRateLimitStatus(attempts, key, t + 1000);
  assert.equal(locked.allowed, false);

  // After 2 minutes + 1ms, lock expires and resets count
  const afterLock = checkRateLimitStatus(attempts, key, t + 120_001);
  assert.equal(afterLock.allowed, true);
  assert.equal(attempts[key], undefined);
});

test('evaluateSuspension distinguishes active, expired, and permanent bans', () => {
  const now = Date.now();
  assert.equal(evaluateSuspension({ isSuspended: false }, now).suspended, false);
  assert.equal(
    evaluateSuspension({ isSuspended: true, suspensionExpires: 'permanente' }, now).suspended,
    true
  );
  assert.equal(
    evaluateSuspension({ isSuspended: true, suspensionExpires: new Date(now + 60_000).toISOString() }, now).suspended,
    true
  );
  const expired = evaluateSuspension(
    { isSuspended: true, suspensionExpires: new Date(now - 60_000).toISOString() },
    now
  );
  assert.equal(expired.suspended, false);
  assert.equal(expired.expired, true);
});

test('recovery tokens verify single-use digests and respect expiration', () => {
  const now = Date.now();
  const { rawToken, record } = createRecoveryTokenRecord(now, 15 * 60 * 1000, 'founder');
  assert.equal(verifyRecoveryToken(record, rawToken, now + 1000), true);
  assert.equal(verifyRecoveryToken(record, 'bad-token', now + 1000), false);
  assert.equal(verifyRecoveryToken(record, rawToken, now + 16 * 60 * 1000), false);
});

test('revokeUserSessions deletes matching sessions while optionally keeping current session', () => {
  const sessions: Record<string, any> = {
    t1: { token: 't1', username: 'testfan', createdAt: 1, expiresAt: 9999999999999 },
    t2: { token: 't2', username: 'TestFan', createdAt: 1, expiresAt: 9999999999999 },
    t3: { token: 't3', username: 'aurora_fan', createdAt: 1, expiresAt: 9999999999999 }
  };
  const removedKeepingT1 = revokeUserSessions(sessions, 'testfan', 't1');
  assert.equal(removedKeepingT1, 1);
  assert.ok(sessions.t1);
  assert.equal(sessions.t2, undefined);
  assert.ok(sessions.t3);

  const removedAll = revokeUserSessions(sessions, 'testfan');
  assert.equal(removedAll, 1);
  assert.equal(sessions.t1, undefined);
  assert.ok(sessions.t3);
});

test('shouldAssignFirstServerAdmin grants admin only when no admin/founder exists yet', () => {
  assert.equal(shouldAssignFirstServerAdmin({}, ''), true);
  assert.equal(shouldAssignFirstServerAdmin({ fan1: { accountType: 'fan', isFounder: false } }, ''), true);
  assert.equal(
    shouldAssignFirstServerAdmin(
      { founder1: { accountType: 'admin', isFounder: true } },
      'founder1'
    ),
    false
  );
  assert.equal(
    shouldAssignFirstServerAdmin(
      { admin1: { accountType: 'admin', isFounder: false }, fan1: { accountType: 'fan' } },
      ''
    ),
    false
  );
  assert.equal(
    shouldAssignFirstServerAdmin(
      { firstUser: { accountType: 'fan', isFounder: false } },
      'firstUser'
    ),
    false
  );
});

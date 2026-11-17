import test from 'node:test';
import assert from 'node:assert/strict';
import {
  extractExpressCredentials,
  getSupabaseEnvOverrides,
  getSupabaseStatus,
  isJwtToken
} from './supabaseServer';

test('extractExpressCredentials reads Bearer token and apikey header', () => {
  const req = {
    headers: {
      authorization: 'Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig',
      apikey: 'sb_publishable_test_key'
    }
  } as any;

  const creds = extractExpressCredentials(req);
  assert.equal(creds.token, 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.sig');
  assert.equal(creds.apikey, 'sb_publishable_test_key');
});

test('getSupabaseEnvOverrides ignores masked bullet placeholders', () => {
  const prevUrl = process.env.SUPABASE_URL;
  const prevSecret = process.env.SUPABASE_SECRET_KEY;
  const prevPub = process.env.SUPABASE_PUBLISHABLE_KEY;

  try {
    process.env.SUPABASE_URL = 'https://example.supabase.co';
    process.env.SUPABASE_PUBLISHABLE_KEY = 'sb_publishable_real_123';
    process.env.SUPABASE_SECRET_KEY = 'sb_secret_cy80h••••••••••••••••••••';

    const overrides = getSupabaseEnvOverrides();
    assert.equal(overrides.url, 'https://example.supabase.co');
    assert.deepEqual(overrides.publishableKeys, { default: 'sb_publishable_real_123' });
    assert.equal(overrides.secretKeys, undefined);
  } finally {
    if (prevUrl === undefined) delete process.env.SUPABASE_URL;
    else process.env.SUPABASE_URL = prevUrl;

    if (prevSecret === undefined) delete process.env.SUPABASE_SECRET_KEY;
    else process.env.SUPABASE_SECRET_KEY = prevSecret;

    if (prevPub === undefined) delete process.env.SUPABASE_PUBLISHABLE_KEY;
    else process.env.SUPABASE_PUBLISHABLE_KEY = prevPub;
  }
});

test('getSupabaseStatus reports unconfigured cleanly when SUPABASE_URL is absent', () => {
  const prevUrl = process.env.SUPABASE_URL;
  const prevViteUrl = process.env.VITE_SUPABASE_URL;

  try {
    delete process.env.SUPABASE_URL;
    delete process.env.VITE_SUPABASE_URL;
    const status = getSupabaseStatus();
    assert.equal(status.configured, false);
    assert.equal(status.url, null);
  } finally {
    if (prevUrl !== undefined) process.env.SUPABASE_URL = prevUrl;
    if (prevViteUrl !== undefined) process.env.VITE_SUPABASE_URL = prevViteUrl;
  }
});

test('isJwtToken detects 3-segment JWT strings without matching hex session tokens', () => {
  assert.equal(isJwtToken('eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1MSJ9.abc'), true);
  assert.equal(isJwtToken('a3f4b5c6d7e8f90123456789abcdef'), false);
  assert.equal(isJwtToken(null), false);
});

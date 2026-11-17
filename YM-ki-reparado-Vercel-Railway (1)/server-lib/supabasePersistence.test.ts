import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeJsonHash,
  diffChangedKeys,
  getSupabasePersistenceConfig,
  getSupabasePersistenceMetrics,
  seedSyncedHashes
} from './supabasePersistence';

test('computeJsonHash produces identical SHA-256 digests for equal payloads and different digests on change', () => {
  const a = computeJsonHash([{ id: 'p1', title: 'Hola' }]);
  const b = computeJsonHash([{ id: 'p1', title: 'Hola' }]);
  const c = computeJsonHash([{ id: 'p1', title: 'Hola 2' }]);

  assert.equal(a, b);
  assert.notEqual(a, c);
});

test('diffChangedKeys returns only keys whose content hash changed', () => {
  const initialState = {
    allProfiles: { alice: { coins: 100 } },
    posts: [{ id: '1', text: 'first' }],
    forums: [{ id: 'f1', name: 'General' }]
  };
  seedSyncedHashes(initialState);

  const updatedState = {
    allProfiles: { alice: { coins: 100 } },
    posts: [{ id: '1', text: 'first' }, { id: '2', text: 'second' }],
    forums: [{ id: 'f1', name: 'General' }]
  };

  const changed = diffChangedKeys(updatedState, new Map(
    Object.entries(initialState).map(([k, v]) => [k, computeJsonHash(v)])
  ));

  assert.equal(changed.length, 1);
  assert.equal(changed[0].key, 'posts');
});

test('getSupabasePersistenceConfig ignores masked or empty values and reports unconfigured cleanly', () => {
  const prevUrl = process.env.SUPABASE_URL;
  const prevViteUrl = process.env.VITE_SUPABASE_URL;
  const prevService = process.env.SUPABASE_SERVICE_ROLE_KEY;

  try {
    process.env.SUPABASE_URL = 'https://example.supabase.co';
    process.env.SUPABASE_SERVICE_ROLE_KEY = 'sb_secret_cy80h••••••••••••••••••••';
    const maskedCfg = getSupabasePersistenceConfig();
    assert.equal(maskedCfg.configured, false);
    assert.equal(maskedCfg.serviceRoleKey, null);

    delete process.env.SUPABASE_URL;
    delete process.env.VITE_SUPABASE_URL;
    delete process.env.SUPABASE_SERVICE_ROLE_KEY;
    const emptyCfg = getSupabasePersistenceConfig();
    assert.equal(emptyCfg.configured, false);

    const metrics = getSupabasePersistenceMetrics();
    assert.equal(metrics.configured, false);
  } finally {
    if (prevUrl !== undefined) process.env.SUPABASE_URL = prevUrl;
    else delete process.env.SUPABASE_URL;

    if (prevViteUrl !== undefined) process.env.VITE_SUPABASE_URL = prevViteUrl;
    else delete process.env.VITE_SUPABASE_URL;

    if (prevService !== undefined) process.env.SUPABASE_SERVICE_ROLE_KEY = prevService;
    else delete process.env.SUPABASE_SERVICE_ROLE_KEY;
  }
});

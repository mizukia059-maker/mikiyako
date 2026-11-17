import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import {
  preserveAndSanitizeProfiles,
  atomicWriteJsonFile,
  readJsonWithBackupFallback,
  WriteQueue
} from './dbPersistence';

test('preserveAndSanitizeProfiles never deletes profiles without credentials and flags pending recovery', () => {
  const profiles: Record<string, any> = {
    testfan: { username: 'testfan', accountType: 'fan' },
    legacyUser: { username: 'legacyUser', accountType: 'fan', coins: 300 }
  };
  const creds: Record<string, any> = {
    testfan: { salt: 'abc', hash: 'def' }
  };

  const summary = preserveAndSanitizeProfiles(profiles, creds);
  assert.equal(summary.totalProfiles, 2);
  assert.deepEqual(summary.pendingRecoveryUsers, ['legacyUser']);
  assert.equal(profiles.legacyUser.credentialsPendingRecovery, true);
  assert.equal(profiles.legacyUser.accessStatus, 'pending_recovery');
  assert.equal(profiles.legacyUser.coins, 300);
  assert.equal(profiles.testfan.accessStatus, 'active');
  assert.equal(profiles.testfan.credentialsPendingRecovery, undefined);
});

test('atomicWriteJsonFile and readJsonWithBackupFallback recover from corrupted primary db', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ymki-persist-'));
  const dbPath = path.join(tmpDir, 'db.json');
  const backupPath = path.join(tmpDir, 'backup_latest.json');

  try {
    atomicWriteJsonFile(backupPath, { registeredUsersCount: 2, allProfiles: { testfan: { coins: 500 } } });
    fs.writeFileSync(dbPath, '{ corrupted json !!!', 'utf-8');

    const loaded = readJsonWithBackupFallback<any>(dbPath, backupPath);
    assert.equal(loaded.source, 'backup');
    assert.equal(loaded.data.registeredUsersCount, 2);
    assert.equal(loaded.data.allProfiles.testfan.coins, 500);
  } finally {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
});

test('WriteQueue executes queued tasks strictly in order', async () => {
  const queue = new WriteQueue();
  const order: number[] = [];
  await Promise.all([
    queue.enqueue(async () => {
      await new Promise((r) => setTimeout(r, 15));
      order.push(1);
    }),
    queue.enqueue(() => {
      order.push(2);
    }),
    queue.enqueue(() => {
      order.push(3);
    })
  ]);
  assert.deepEqual(order, [1, 2, 3]);
});

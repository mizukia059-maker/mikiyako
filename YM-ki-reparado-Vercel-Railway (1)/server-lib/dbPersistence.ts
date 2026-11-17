import fs from 'fs';
import path from 'path';

export interface ProfilePreservationSummary {
  totalProfiles: number;
  pendingRecoveryUsers: string[];
}

export function preserveAndSanitizeProfiles(
  allProfiles: Record<string, any>,
  userCredentials: Record<string, any>
): ProfilePreservationSummary {
  const pendingRecoveryUsers: string[] = [];

  for (const uname of Object.keys(allProfiles)) {
    const profile = allProfiles[uname];
    if (!profile || typeof profile !== 'object') continue;

    // Resolve credential case-insensitively if needed, preferring exact key
    let cred = userCredentials[uname];
    if (!cred) {
      const credKey = Object.keys(userCredentials).find((k) => k.toLowerCase() === uname.toLowerCase());
      if (credKey) cred = userCredentials[credKey];
    }

    if (!cred || !cred.hash || !cred.salt) {
      // STRICT DATA PRESERVATION RULE: Never delete profiles lacking credentials.
      // Preserve the profile and flag access as pending recovery.
      profile.credentialsPendingRecovery = true;
      profile.accessStatus = 'pending_recovery';
      pendingRecoveryUsers.push(uname);
    } else {
      if (profile.credentialsPendingRecovery) {
        delete profile.credentialsPendingRecovery;
      }
      if (!profile.accessStatus || profile.accessStatus === 'pending_recovery') {
        profile.accessStatus = 'active';
      }
    }
  }

  return {
    totalProfiles: Object.keys(allProfiles).length,
    pendingRecoveryUsers
  };
}

export function atomicWriteJsonFile(targetPath: string, data: unknown): void {
  const dir = path.dirname(targetPath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
  const serialized = JSON.stringify(data, null, 2);
  const tempPath = `${targetPath}.${process.pid}.${Date.now()}.${Math.floor(Math.random() * 100000)}.tmp`;
  try {
    fs.writeFileSync(tempPath, serialized, 'utf-8');
    fs.renameSync(tempPath, targetPath);
  } catch (err) {
    try {
      if (fs.existsSync(tempPath)) fs.unlinkSync(tempPath);
    } catch {
      // ignore cleanup failure
    }
    throw err;
  }
}

export interface LoadJsonResult<T> {
  data: T | null;
  source: 'primary' | 'backup' | 'none';
  error?: string;
}

export function readJsonWithBackupFallback<T>(dbPath: string, backupPath: string): LoadJsonResult<T> {
  let primaryError: string | undefined;

  if (fs.existsSync(dbPath)) {
    try {
      const raw = fs.readFileSync(dbPath, 'utf-8');
      if (raw.trim().length > 0) {
        return { data: JSON.parse(raw) as T, source: 'primary' };
      }
      primaryError = 'Primary db.json is empty';
    } catch (err: any) {
      primaryError = err?.message || 'Corrupted primary db.json';
    }
  }

  if (fs.existsSync(backupPath)) {
    try {
      const rawBackup = fs.readFileSync(backupPath, 'utf-8');
      if (rawBackup.trim().length > 0) {
        return {
          data: JSON.parse(rawBackup) as T,
          source: 'backup',
          error: primaryError
        };
      }
    } catch (err: any) {
      return {
        data: null,
        source: 'none',
        error: primaryError || err?.message || 'Corrupted backup JSON'
      };
    }
  }

  return { data: null, source: 'none', error: primaryError };
}

export class WriteQueue {
  private chain: Promise<void> = Promise.resolve();

  enqueue(task: () => void | Promise<void>): Promise<void> {
    const next = this.chain.then(task, task);
    this.chain = next.catch(() => {});
    return next;
  }
}

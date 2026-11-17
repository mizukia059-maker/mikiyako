import crypto from 'crypto';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { WriteQueue } from './dbPersistence';

export interface SupabasePersistenceConfig {
  configured: boolean;
  url: string | null;
  serviceRoleKey: string | null;
}

export interface SupabasePersistenceMetrics {
  configured: boolean;
  lastSuccessfulWriteAt: string | null;
  lastError: string | null;
}

function cleanEnvValue(value: string | undefined): string | null {
  if (!value) return null;
  const trimmed = value.trim();
  if (!trimmed) return null;
  if (trimmed.includes('•') || trimmed.includes('your-project-id')) return null;
  return trimmed;
}

export function getSupabasePersistenceConfig(): SupabasePersistenceConfig {
  const url =
    cleanEnvValue(process.env.SUPABASE_URL) ||
    cleanEnvValue(process.env.VITE_SUPABASE_URL);
  const serviceRoleKey = cleanEnvValue(process.env.SUPABASE_SERVICE_ROLE_KEY);

  return {
    configured: Boolean(url && serviceRoleKey),
    url,
    serviceRoleKey
  };
}

let cachedClient: SupabaseClient | null = null;
let cachedClientSignature = '';

export function getSupabaseServiceClient(): SupabaseClient | null {
  const cfg = getSupabasePersistenceConfig();
  if (!cfg.configured || !cfg.url || !cfg.serviceRoleKey) {
    return null;
  }

  const signature = `${cfg.url}::${cfg.serviceRoleKey.slice(0, 8)}:${cfg.serviceRoleKey.length}`;
  if (cachedClient && cachedClientSignature === signature) {
    return cachedClient;
  }

  cachedClient = createClient(cfg.url, cfg.serviceRoleKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
      detectSessionInUrl: false
    }
  });
  cachedClientSignature = signature;
  return cachedClient;
}

export function computeJsonHash(value: unknown): string {
  const serialized = JSON.stringify(value === undefined ? null : value);
  return crypto.createHash('sha256').update(serialized).digest('hex');
}

export function diffChangedKeys(
  snapshot: Record<string, unknown>,
  previousHashes: Map<string, string>
): Array<{ key: string; value: unknown; hash: string }> {
  const changed: Array<{ key: string; value: unknown; hash: string }> = [];
  for (const key of Object.keys(snapshot)) {
    const val = snapshot[key] === undefined ? null : snapshot[key];
    const hash = computeJsonHash(val);
    if (previousHashes.get(key) !== hash) {
      changed.push({ key, value: val, hash });
    }
  }
  return changed;
}

const lastSyncedHashes = new Map<string, string>();
const supabaseWriteQueue = new WriteQueue();
let debounceTimer: ReturnType<typeof setTimeout> | null = null;
let pendingSnapshot: Record<string, unknown> | null = null;
let pendingGeneration = 0;

let lastSuccessfulWriteAt: string | null = null;
let lastSupabaseError: string | null = null;

export function getSupabasePersistenceMetrics(): SupabasePersistenceMetrics {
  return {
    configured: getSupabasePersistenceConfig().configured,
    lastSuccessfulWriteAt,
    lastError: lastSupabaseError
  };
}

export function seedSyncedHashes(snapshot: Record<string, unknown>): void {
  lastSyncedHashes.clear();
  for (const key of Object.keys(snapshot)) {
    lastSyncedHashes.set(key, computeJsonHash(snapshot[key]));
  }
}

async function upsertRowsWithRetry(
  client: SupabaseClient,
  rows: Array<{ key: string; value: unknown; updated_at: string }>,
  generationAtStart: number,
  maxAttempts = 4
): Promise<boolean> {
  let delayMs = 750;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      // Chunk large batches safely so we never exceed PostgREST payload limits
      const chunkSize = 15;
      for (let i = 0; i < rows.length; i += chunkSize) {
        const chunk = rows.slice(i, i + chunkSize);
        const { error } = await client
          .from('app_state')
          .upsert(chunk, { onConflict: 'key' });
        if (error) {
          throw new Error(error.message || 'Supabase upsert error');
        }
      }
      return true;
    } catch (err: any) {
      lastSupabaseError = err?.message || 'Error al escribir en Supabase app_state';
      if (attempt < maxAttempts && generationAtStart === pendingGeneration) {
        await new Promise((resolve) => setTimeout(resolve, delayMs));
        delayMs *= 2;
      } else {
        return false;
      }
    }
  }
  return false;
}

export async function flushSupabaseSyncNow(
  snapshotOverride?: Record<string, unknown>
): Promise<boolean> {
  const client = getSupabaseServiceClient();
  const snapshot = snapshotOverride || pendingSnapshot;
  if (!client || !snapshot) return false;

  const generationAtStart = pendingGeneration;
  return new Promise<boolean>((resolve) => {
    void supabaseWriteQueue.enqueue(async () => {
      try {
        const changed = diffChangedKeys(snapshot, lastSyncedHashes);
        if (changed.length === 0) {
          resolve(true);
          return;
        }

        const nowIso = new Date().toISOString();
        const rows = changed.map((item) => ({
          key: item.key,
          value: item.value,
          updated_at: nowIso
        }));

        const ok = await upsertRowsWithRetry(client, rows, generationAtStart);
        if (ok) {
          for (const item of changed) {
            lastSyncedHashes.set(item.key, item.hash);
          }
          lastSuccessfulWriteAt = nowIso;
          lastSupabaseError = null;
          resolve(true);
        } else {
          console.warn('Supabase sync failed after retries; local db.json remains up to date.');
          resolve(false);
        }
      } catch (err: any) {
        lastSupabaseError = err?.message || 'Error inesperado sincronizando con Supabase';
        console.warn('Supabase sync queue warning:', lastSupabaseError);
        resolve(false);
      }
    });
  });
}

export function scheduleSupabaseSync(
  snapshot: Record<string, unknown>,
  debounceMs = 500
): void {
  if (!getSupabasePersistenceConfig().configured) return;

  pendingSnapshot = snapshot;
  pendingGeneration += 1;

  if (debounceTimer) {
    clearTimeout(debounceTimer);
  }

  debounceTimer = setTimeout(() => {
    debounceTimer = null;
    const toSync = pendingSnapshot;
    if (toSync) {
      void flushSupabaseSyncNow(toSync);
    }
  }, debounceMs);
}

export async function hydrateDatabaseFromSupabase<T extends Record<string, any>>(
  localDb: T,
  sanitizeFn: (data: T) => T,
  persistLocalMirrorFn: (data: T) => void
): Promise<{ db: T; source: 'supabase' | 'seeded-supabase' | 'local'; warning?: string }> {
  const client = getSupabaseServiceClient();
  if (!client) {
    return { db: localDb, source: 'local' };
  }

  try {
    const { data: rows, error } = await client
      .from('app_state')
      .select('key, value');

    if (error) {
      lastSupabaseError = error.message || 'Error consultando app_state en Supabase';
      console.warn('No se pudo leer app_state en Supabase, usando db.json local:', lastSupabaseError);
      return {
        db: localDb,
        source: 'local',
        warning: `Supabase no disponible al iniciar (${lastSupabaseError}); usando respaldo local db.json.`
      };
    }

    if (Array.isArray(rows) && rows.length > 0) {
      const hydrated = { ...localDb } as Record<string, any>;
      for (const row of rows) {
        if (row && typeof row.key === 'string') {
          hydrated[row.key] = row.value;
        }
      }
      const sanitized = sanitizeFn(hydrated as T);
      seedSyncedHashes(sanitized);
      persistLocalMirrorFn(sanitized);
      lastSupabaseError = null;
      return { db: sanitized, source: 'supabase' };
    }

    // Table is empty: perform automatic one-time initial seed from local db.json
    const sanitizedLocal = sanitizeFn({ ...localDb });
    const nowIso = new Date().toISOString();
    const initialRows = Object.keys(sanitizedLocal).map((key) => ({
      key,
      value: sanitizedLocal[key] === undefined ? null : sanitizedLocal[key],
      updated_at: nowIso
    }));

    const seeded = await upsertRowsWithRetry(client, initialRows, pendingGeneration, 3);
    if (seeded) {
      seedSyncedHashes(sanitizedLocal);
      lastSuccessfulWriteAt = nowIso;
      lastSupabaseError = null;
      return { db: sanitizedLocal, source: 'seeded-supabase' };
    }

    return {
      db: sanitizedLocal,
      source: 'local',
      warning: `No se pudo sembrar app_state en Supabase (${lastSupabaseError || 'error de escritura'}); operando con db.json local.`
    };
  } catch (err: any) {
    lastSupabaseError = err?.message || 'Error conectando con Supabase al iniciar';
    console.warn('Error conectando con Supabase al iniciar; usando db.json local:', lastSupabaseError);
    return {
      db: localDb,
      source: 'local',
      warning: `Supabase inalcanzable al iniciar (${lastSupabaseError}); operando con db.json local.`
    };
  }
}

export async function checkSupabaseReachable(): Promise<boolean> {
  const client = getSupabaseServiceClient();
  if (!client) return false;

  try {
    const { error } = await client
      .from('app_state')
      .select('key')
      .limit(1);
    if (error) {
      lastSupabaseError = error.message || 'app_state query failed';
      return false;
    }
    return true;
  } catch (err: any) {
    lastSupabaseError = err?.message || 'Supabase unreachable';
    return false;
  }
}

export async function uploadBufferToSupabaseStorage(
  uniqueFileName: string,
  buffer: Buffer,
  mimeType: string,
  bucket = 'uploads'
): Promise<{ url: string | null; error?: string }> {
  const client = getSupabaseServiceClient();
  if (!client) {
    return { url: null, error: 'Supabase no configurado' };
  }

  try {
    const { error: uploadError } = await client.storage
      .from(bucket)
      .upload(uniqueFileName, buffer, {
        contentType: mimeType,
        upsert: false
      });

    if (uploadError) {
      return { url: null, error: uploadError.message };
    }

    const { data: publicData } = client.storage
      .from(bucket)
      .getPublicUrl(uniqueFileName);

    return { url: publicData?.publicUrl || null };
  } catch (err: any) {
    return { url: null, error: err?.message || 'Error subiendo archivo a Supabase Storage' };
  }
}

import type { Request, Response, NextFunction } from 'express';
import {
  fromSupabaseUrl,
  type AuthModeWithKey,
  type AuthResult,
  type SupabaseEnv
} from '@supabase/server';
import {
  createAdminClient,
  createContextClient,
  resolveEnv,
  verifyCredentials,
  type VerifyCredentialsOptions
} from '@supabase/server/core';
import type { SupabaseClient } from '@supabase/supabase-js';

export interface SupabaseStatusSummary {
  configured: boolean;
  url: string | null;
  hasPublishableKey: boolean;
  hasSecretKey: boolean;
  hasJwks: boolean;
  error?: string;
}

export interface ExpressSupabaseContext {
  auth: AuthResult;
  supabase: SupabaseClient | null;
  supabaseAdmin: SupabaseClient | null;
}

function isUsableValue(val: string | undefined): val is string {
  if (!val) return false;
  const trimmed = val.trim();
  if (!trimmed) return false;
  if (trimmed.includes('•') || trimmed.includes('your-project-id')) return false;
  return true;
}

export function getSupabaseEnvOverrides(): Partial<SupabaseEnv> {
  const overrides: Partial<SupabaseEnv> = {};

  const rawUrl = isUsableValue(process.env.SUPABASE_URL)
    ? process.env.SUPABASE_URL.trim()
    : isUsableValue(process.env.VITE_SUPABASE_URL)
      ? process.env.VITE_SUPABASE_URL.trim()
      : undefined;

  if (rawUrl) {
    overrides.url = rawUrl;
  }

  // Only inject singular fallback overrides if plural keys are not explicitly set
  if (!isUsableValue(process.env.SUPABASE_PUBLISHABLE_KEYS)) {
    const pubKey = isUsableValue(process.env.SUPABASE_PUBLISHABLE_KEY)
      ? process.env.SUPABASE_PUBLISHABLE_KEY.trim()
      : isUsableValue(process.env.VITE_SUPABASE_PUBLISHABLE_KEY)
        ? process.env.VITE_SUPABASE_PUBLISHABLE_KEY.trim()
        : undefined;
    if (pubKey) {
      overrides.publishableKeys = { default: pubKey };
    }
  }

  if (!isUsableValue(process.env.SUPABASE_SECRET_KEYS) && isUsableValue(process.env.SUPABASE_SECRET_KEY)) {
    overrides.secretKeys = { default: process.env.SUPABASE_SECRET_KEY.trim() };
  }

  if (!isUsableValue(process.env.SUPABASE_JWKS) && isUsableValue(process.env.SUPABASE_JWKS_URL)) {
    try {
      const parsed = new URL(process.env.SUPABASE_JWKS_URL.trim());
      overrides.jwks = parsed;
    } catch {
      // Let resolveEnv handle / ignore invalid URL
    }
  }

  return overrides;
}

export function resolveSupabaseEnv() {
  return resolveEnv(getSupabaseEnvOverrides());
}

export function getSupabaseStatus(): SupabaseStatusSummary {
  const { data: env, error } = resolveSupabaseEnv();
  if (error || !env) {
    return {
      configured: false,
      url: null,
      hasPublishableKey: false,
      hasSecretKey: false,
      hasJwks: false,
      error: error?.message || 'SUPABASE_URL no configurado.'
    };
  }

  return {
    configured: true,
    url: env.url,
    hasPublishableKey: Object.keys(env.publishableKeys || {}).length > 0,
    hasSecretKey: Object.keys(env.secretKeys || {}).length > 0,
    hasJwks: Boolean(env.jwks)
  };
}

export function extractExpressCredentials(req: Request): { token: string | null; apikey: string | null } {
  const rawAuth = req.headers.authorization;
  let token: string | null = null;
  if (typeof rawAuth === 'string' && rawAuth.toLowerCase().startsWith('bearer ')) {
    const candidate = rawAuth.slice(7).trim();
    if (candidate) token = candidate;
  }

  const rawApiKey = req.headers.apikey;
  const apikey =
    typeof rawApiKey === 'string' && rawApiKey.trim().length > 0
      ? rawApiKey.trim()
      : Array.isArray(rawApiKey) && typeof rawApiKey[0] === 'string' && rawApiKey[0].trim().length > 0
        ? rawApiKey[0].trim()
        : null;

  return { token, apikey };
}

export function isJwtToken(token: string | null | undefined): boolean {
  if (!token || typeof token !== 'string') return false;
  const parts = token.split('.');
  return parts.length === 3 && parts.every((p) => p.length > 0);
}

export async function verifyExpressSupabaseAuth(
  req: Request,
  options: Omit<VerifyCredentialsOptions, 'env'> & { env?: Partial<SupabaseEnv> } = { auth: 'user' }
) {
  const overrides = { ...getSupabaseEnvOverrides(), ...(options.env || {}) };
  const { data: resolvedEnv } = resolveEnv(overrides);
  const credentials = extractExpressCredentials(req);

  const issuer =
    options.issuer ??
    (resolvedEnv?.url ? fromSupabaseUrl(resolvedEnv.url) : undefined);

  return verifyCredentials(credentials, {
    auth: options.auth ?? 'user',
    audience: options.audience,
    issuer,
    env: overrides
  });
}

export function createExpressSupabaseClients(
  auth?: Pick<AuthResult, 'token' | 'keyName' | 'authMode'>,
  envOverrides?: Partial<SupabaseEnv>
): { supabase: SupabaseClient | null; supabaseAdmin: SupabaseClient | null } {
  const env = { ...getSupabaseEnvOverrides(), ...(envOverrides || {}) };
  const { data: resolved } = resolveEnv(env);
  if (!resolved) {
    return { supabase: null, supabaseAdmin: null };
  }

  let supabase: SupabaseClient | null = null;
  let supabaseAdmin: SupabaseClient | null = null;

  const hasPubKey = Object.keys(resolved.publishableKeys || {}).length > 0;
  if (hasPubKey) {
    try {
      const clientAuth =
        auth?.authMode === 'user' && auth.token
          ? { token: auth.token, keyName: auth.keyName }
          : auth?.keyName && auth.authMode === 'publishable'
            ? { keyName: auth.keyName }
            : undefined;
      supabase = createContextClient({
        ...(clientAuth ? { auth: clientAuth } : {}),
        env
      });
    } catch {
      supabase = null;
    }
  }

  const hasSecretKey = Object.keys(resolved.secretKeys || {}).length > 0;
  if (hasSecretKey) {
    try {
      const adminAuth =
        auth?.keyName && auth.authMode === 'secret'
          ? { keyName: auth.keyName }
          : undefined;
      supabaseAdmin = createAdminClient({
        ...(adminAuth ? { auth: adminAuth } : {}),
        env
      });
    } catch {
      supabaseAdmin = null;
    }
  }

  return { supabase, supabaseAdmin };
}

export function requireSupabaseAuth(
  auth: AuthModeWithKey | AuthModeWithKey[] = 'user'
) {
  return async (req: Request, res: Response, next: NextFunction) => {
    const { data, error } = await verifyExpressSupabaseAuth(req, { auth });
    if (error || !data) {
      const status = error?.status || 401;
      return res.status(status).json({
        error: error?.message || 'Autenticación de Supabase requerida.',
        code: error?.code || 'AUTH_ERROR',
        hint: error?.hint
      });
    }

    const clients = createExpressSupabaseClients(data);
    (req as any).supabaseContext = {
      auth: data,
      ...clients
    } satisfies ExpressSupabaseContext;

    next();
  };
}

const API_BASE_URL = (import.meta.env.VITE_API_BASE_URL || '').trim().replace(/\/$/, '');

/** Resolve API paths against the separately deployed Express server when configured. */
export const resolveApiUrl = (url: string): string => {
  if (/^https?:\/\//i.test(url)) return url;
  if (!API_BASE_URL) return url;
  return `${API_BASE_URL}${url.startsWith('/') ? url : `/${url}`}`;
};

export const getStoredAuthToken = (): string | null => {
  try {
    return localStorage.getItem('ym_auth_token');
  } catch {
    return null;
  }
};

export const apiFetch = async (url: string, init?: RequestInit): Promise<Response> => {
  try {
    const token = getStoredAuthToken();
    const headers = new Headers(init?.headers || {});
    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`);
    }
    return await fetch(resolveApiUrl(url), { ...init, headers });
  } catch (err) {
    console.warn('API fetch warning:', err);
    return new Response(JSON.stringify({ error: 'Error de conexión con el servidor.' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
};

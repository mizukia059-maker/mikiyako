# Guía de Persistencia e Integración de Supabase en YM-ki (Fase 1)

Este documento describe cómo funciona actualmente la persistencia de YM-ki con Supabase (Postgres + Storage) y respaldo local automático.

## 1. Variables de Entorno

Configura estas variables en tu entorno (o en los Secretos de tu hosting / `.env` local):

```env
# Requeridas para que el backend (server.ts) persista en Supabase:
SUPABASE_URL=https://<tu-proyecto-id>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOi...

# Opcionales para el cliente frontend (Vite):
VITE_SUPABASE_URL=https://<tu-proyecto-id>.supabase.co
VITE_SUPABASE_ANON_KEY=eyJhbGciOi...
```

> **Seguridad:** `SUPABASE_SERVICE_ROLE_KEY` solo se usa en el servidor (`server.ts` / `server-lib/supabasePersistence.ts`). Nunca se expone al navegador ni se imprime en logs.

## 2. Migración SQL (Fase 1)

1. Entra a tu proyecto en [Supabase](https://supabase.com/).
2. Abre **SQL Editor** → **New query**.
3. Copia y ejecuta el contenido completo del archivo:
   `supabase/migrations/20261114_app_state.sql`
4. Esta migración crea:
   - La tabla `public.app_state (key TEXT PRIMARY KEY, value JSONB NOT NULL DEFAULT '{}'::jsonb, updated_at TIMESTAMPTZ DEFAULT NOW())`.
   - **Row Level Security (RLS) activado SIN políticas** en `public.app_state`: ningún usuario desde el navegador puede leer o modificar esta tabla directamente; solo el backend con `SUPABASE_SERVICE_ROLE_KEY` puede acceder.
   - El bucket público de solo lectura **`uploads`** en Supabase Storage (con política `SELECT` pública y subidas restringidas al backend).

*(Nota: el archivo `supabase/migrations/20261108_initial_schema.sql` corresponde a un esquema relacional futuro de referencia; la persistencia activa en Fase 1 utiliza `public.app_state`.)*

## 3. Cómo funciona la Arquitectura Dual (Supabase + Respaldo Local)

1. **Al arrancar el servidor (`startServer` en `server.ts`):**
   - Primero lee el respaldo local `data/db.json` (o `data/backups/backup_latest.json`).
   - Si `SUPABASE_URL` (o `VITE_SUPABASE_URL`) y `SUPABASE_SERVICE_ROLE_KEY` están configurados, consulta `public.app_state` **antes** de abrir el puerto HTTP (`app.listen`):
     - Si `app_state` ya tiene filas, hidrata `db` en memoria desde Supabase y actualiza el respaldo local `data/db.json`.
     - Si `app_state` está vacío y existe `data/db.json`, migra automáticamente las 57 colecciones de `db` a `app_state` (semilla inicial única).
     - Si Supabase no está configurado o falla la conexión, el servidor arranca igualmente con `data/db.json` sin interrumpir el servicio.
2. **Al guardar cambios (`saveDatabase`):**
   - Todas las rutas `/api/*` siguen operando sobre `db` en memoria y llamando a `saveDatabase(db)` de forma síncrona.
   - `saveDatabase` escribe atómicamente en `data/db.json` + `data/backups/backup_latest.json` y agenda una sincronización a Supabase con **debounce de 500 ms**, **cola serializada única**, **comparación por hash SHA-256 por clave** (solo envía las colecciones que cambiaron) y **reintentos con backoff** si ocurre un fallo temporal.
3. **Subidas de archivos (`POST /api/upload`):**
   - Valida tamaño (máximo 15 MB), tipo MIME y firma binaria (*magic bytes*).
   - Si Supabase está configurado, sube el archivo al bucket `"uploads"` de Supabase Storage y devuelve su URL pública.
   - Si Supabase no está configurado o falla el bucket, guarda el archivo en `public/uploads/` y devuelve `/uploads/<archivo>`.
4. **Diagnóstico (`GET /api/health`):**
   - Reporta `supabaseConfigured`, `supabaseReachable` (ejecutando una consulta real a `public.app_state`) y `lastSupabaseWriteAt` (fecha de la última escritura exitosa a Supabase).

## 4. Fase 2 (Pendiente)

La autenticación actual de usuarios sigue gestionándose mediante `/api/auth/*` y las colecciones `allProfiles`, `userCredentials` y `activeSessions` persistidas en `public.app_state`. La migración a Supabase Auth corresponde a la Fase 2.

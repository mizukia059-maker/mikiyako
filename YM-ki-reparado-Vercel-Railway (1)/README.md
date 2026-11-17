# YM-ki — despliegue Vercel + Railway + Supabase

Este proyecto tiene un frontend React/Vite y un backend Express en `server.ts`. Vercel publica el frontend estático; Railway mantiene el proceso Node/Express y atiende `/api/*`. Supabase conserva el estado persistente y los archivos cuando el Storage está configurado.

## 1) Desplegar el backend en Railway

1. Sube esta carpeta del proyecto a un repositorio GitHub.
2. En Railway crea un proyecto nuevo → **Deploy from GitHub Repo** y selecciona el repositorio.
3. Railway detectará `railway.json`. El comando de build es `npm install && npm run build` y el de inicio es `npm start`.
4. En **Variables** del servicio Railway agrega:
   - `NODE_ENV` = `production`
   - `SUPABASE_URL` = URL del proyecto Supabase (`https://....supabase.co`)
   - `SUPABASE_SERVICE_ROLE_KEY` = clave secreta/service_role de Supabase (solo backend; nunca ponerla en variables `VITE_`)
   - `VITE_SUPABASE_URL` = la misma URL de Supabase (el backend también la acepta como fallback)
   - `PUBLIC_SERVER_URL` = dominio público Railway, por ejemplo `https://tu-servicio.up.railway.app`
   - `CORS_ALLOWED_ORIGINS` = dominio exacto de Vercel, por ejemplo `https://tu-web.vercel.app`. Para varios dominios, sepáralos por comas (incluye el dominio de producción y los previews que quieras permitir).
   - Opcional: `SUPABASE_PUBLISHABLE_KEY`, `SUPABASE_SECRET_KEY`, `SUPABASE_JWKS_URL`, `GEMINI_API_KEY` si se usan esas funciones.
5. Genera un dominio público en Railway (**Settings → Networking → Generate Domain**).
6. Abre `https://TU-DOMINIO-RAILWAY/api/health`. Debe devolver JSON con `"status":"ok"`.

`PORT` lo asigna Railway automáticamente; no lo fijes manualmente.

## 2) Configurar el frontend en Vercel

En el proyecto Vercel → **Settings → Environment Variables**, configura para Production (y también Preview si corresponde):

- `VITE_API_BASE_URL` = dominio público Railway completo, sin barra final, por ejemplo `https://tu-servicio.up.railway.app`
- `VITE_SUPABASE_URL` = URL del proyecto Supabase
- `VITE_SUPABASE_ANON_KEY` = Publishable key (`sb_publishable_...`) o legacy `anon` key

No pongas `SUPABASE_SERVICE_ROLE_KEY` ni `SUPABASE_SECRET_KEY` en Vercel; esas claves privadas van únicamente en Railway.

Después guarda y haz **Redeploy** para que Vite incorpore `VITE_API_BASE_URL` al bundle. Si cambias el dominio Railway, actualiza esta variable y vuelve a desplegar Vercel.

## 3) Supabase

- Ejecuta las migraciones SQL incluidas en `supabase/migrations/` en el SQL Editor del proyecto Supabase, si todavía no lo hiciste.
- En particular, confirma que exista la tabla `app_state` que utiliza `server-lib/supabasePersistence.ts`.
- Para las subidas de archivos, crea un bucket de Storage llamado `uploads` y configura sus políticas según el acceso que necesites.
- No compartas ni publiques `SUPABASE_SERVICE_ROLE_KEY` o `SUPABASE_SECRET_KEY`.

## 4) Pruebas después del despliegue

1. `https://TU-DOMINIO-RAILWAY/api/health` → JSON con `status: ok`.
2. Abre la web Vercel, inicia sesión y prueba una operación que lea y otra que guarde datos.
3. Revisa los logs Railway si la API responde 500.

## Notas importantes sobre datos

- Se conservan `data/db.json` y `data/backups/backup_latest.json` dentro del proyecto como respaldo de origen.
- El disco del contenedor Railway puede ser efímero. La persistencia duradera depende de que Supabase esté correctamente configurado y de que la migración `app_state` esté aplicada. Para archivos, usa Supabase Storage; el fallback local `/uploads` no es almacenamiento duradero entre despliegues.
- No borres la base de datos ni ejecutes migraciones destructivas para solucionar errores de despliegue. Haz una copia de seguridad antes de cualquier cambio de esquema.

## Desarrollo local

```bash
npm install
cp .env.example .env
npm run dev
```

En local deja `VITE_API_BASE_URL` vacío para que el frontend use el mismo servidor Express.

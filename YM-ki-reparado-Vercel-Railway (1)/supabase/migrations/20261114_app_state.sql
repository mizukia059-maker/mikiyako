-- ============================================================================
-- YM-ki Records — Fase 1: Persistencia de estado completo en Supabase (Postgres)
-- ============================================================================
-- Ejecutar este archivo en el SQL Editor del proyecto de Supabase.

-- 1. Tabla principal clave-valor para todas las colecciones de `db`
CREATE TABLE IF NOT EXISTS public.app_state (
  key TEXT PRIMARY KEY,
  value JSONB NOT NULL DEFAULT '{}'::jsonb,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- 2. Activar Row Level Security (RLS) SIN políticas:
--    Ningún cliente del navegador (anon/authenticated) puede leer ni escribir esta tabla.
--    Únicamente el backend usando SUPABASE_SERVICE_ROLE_KEY tiene acceso total.
ALTER TABLE public.app_state ENABLE ROW LEVEL SECURITY;

-- 3. Trigger automático para actualizar `updated_at` en cada escritura
CREATE OR REPLACE FUNCTION public.set_app_state_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = NOW();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_app_state_updated_at ON public.app_state;
CREATE TRIGGER trg_app_state_updated_at
  BEFORE UPDATE ON public.app_state
  FOR EACH ROW
  EXECUTE FUNCTION public.set_app_state_updated_at();

-- 4. Bucket de Storage público de solo lectura llamado "uploads"
--    (Si tu proyecto restringe permisos sobre el esquema storage desde SQL Editor,
--     puedes crearlo manualmente en Storage -> New bucket -> Name: "uploads" -> Public: ON)
INSERT INTO storage.buckets (id, name, public)
VALUES ('uploads', 'uploads', true)
ON CONFLICT (id) DO UPDATE SET public = true;

-- Política de solo lectura pública para archivos en el bucket "uploads"
-- (Subidas y eliminaciones solo las realiza el servidor con SUPABASE_SERVICE_ROLE_KEY)
DROP POLICY IF EXISTS "Public read access for uploads" ON storage.objects;
CREATE POLICY "Public read access for uploads"
  ON storage.objects
  FOR SELECT
  TO public
  USING (bucket_id = 'uploads');

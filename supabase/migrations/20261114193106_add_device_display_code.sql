ALTER TABLE public.devices
  ADD COLUMN device_code text;

CREATE OR REPLACE FUNCTION public.generate_sonix_device_code()
RETURNS text
LANGUAGE plpgsql
VOLATILE
SET search_path = public, pg_temp
AS $function$
DECLARE
  alphabet CONSTANT text := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  candidate text;
  i integer;
BEGIN
  LOOP
    candidate := '';
    FOR i IN 1..10 LOOP
      candidate := candidate || substr(alphabet, floor(random() * 36)::integer + 1, 1);
    END LOOP;
    EXIT WHEN NOT EXISTS (
      SELECT 1 FROM public.devices WHERE device_code = candidate
    );
  END LOOP;
  RETURN candidate;
END;
$function$;

REVOKE ALL ON FUNCTION public.generate_sonix_device_code() FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.generate_sonix_device_code() TO service_role;

ALTER TABLE public.devices
  ALTER COLUMN device_code SET DEFAULT public.generate_sonix_device_code();

UPDATE public.devices
SET device_code = public.generate_sonix_device_code()
WHERE device_code IS NULL;

ALTER TABLE public.devices
  ALTER COLUMN device_code SET NOT NULL,
  ADD CONSTRAINT devices_device_code_format_check
    CHECK (device_code ~ '^[A-Z0-9]{10}$');

CREATE UNIQUE INDEX devices_device_code_key
  ON public.devices (device_code);

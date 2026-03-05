-- why this: application role must not be superuser/bypassrls so Postgres RLS is enforceable.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audity') THEN
        CREATE ROLE audity LOGIN PASSWORD 'audity';
    END IF;
END
$$;

ALTER ROLE audity NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
ALTER DATABASE audity OWNER TO audity;
GRANT ALL PRIVILEGES ON DATABASE audity TO audity;

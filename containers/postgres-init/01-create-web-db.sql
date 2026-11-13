-- Create the buggy_web database used by the Web dashboard.
--
-- Postgres auto-runs files in /docker-entrypoint-initdb.d/ on first startup
-- (only when data volume is empty). This ensures buggy_web exists
-- alongside the litellm database created by POSTGRES_DB.
--
-- To apply to an existing deployment without data loss, create the DB
-- manually: `docker exec buggy-postgres psql -U buggy -c "CREATE DATABASE buggy_web;"`

CREATE DATABASE buggy_web;
GRANT ALL PRIVILEGES ON DATABASE buggy_web TO buggy;

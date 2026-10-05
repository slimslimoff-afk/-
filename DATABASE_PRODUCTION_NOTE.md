# Database production gate

v10.0's current persistence layer uses SQLite. Render deployment can be used
for the first functional validation, but SQLite on an ephemeral web-service
filesystem must NOT be treated as durable production storage.

Before public launch:
1. migrate the persistence layer to PostgreSQL;
2. use Render Postgres (or another managed PostgreSQL);
3. move all DB access behind a PostgreSQL connection layer;
4. run schema migration and backup/restore tests.

Therefore the Render Free deployment prepared here is a **functional MVP
test environment**, not the final durable production database.

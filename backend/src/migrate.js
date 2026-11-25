import 'dotenv/config';
import pg from 'pg';
import { readdir, readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
const { Pool } = pg;
const pool = new Pool({ connectionString: process.env.DATABASE_URL, max: 2 });
const here = dirname(fileURLToPath(import.meta.url));
const migrationDir = join(here, '..', 'migrations');

try {
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [812734611]);
    await client.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
      name TEXT PRIMARY KEY,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
    const files = (await readdir(migrationDir)).filter(name => name.endsWith('.sql')).sort();
    for (const name of files) {
      const exists = await client.query('SELECT 1 FROM schema_migrations WHERE name=$1', [name]);
      if (exists.rowCount) continue;
      const sql = await readFile(join(migrationDir, name), 'utf8');
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations(name) VALUES($1)', [name]);
        await client.query('COMMIT');
        console.log(`Applied migration: ${name}`);
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      }
    }
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [812734611]);
    client.release();
  }
} finally {
  await pool.end();
}

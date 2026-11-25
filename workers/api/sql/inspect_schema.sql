-- Read-only inspection of the existing D1 schema. Safe to run in Cloudflare D1 Console.
SELECT name, sql
FROM sqlite_master
WHERE type = 'table'
  AND name NOT LIKE 'sqlite_%'
ORDER BY name;

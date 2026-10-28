# Database migrations

The schema is versioned with [Doctrine Migrations](https://www.doctrine-project.org/projects/doctrine-migrations/en/3.9/)
(`doctrine/doctrine-migrations-bundle` 3.7, Symfony 7.4 / DBAL 4). Up to and including 2.0.0
the Docker entrypoint ran `doctrine:schema:update --force` at every boot; now it runs
`antispam:db:upgrade`, so every install (Docker or on-premise) goes through the same,
reviewed SQL.

| What | Where |
| --- | --- |
| Migrations | `migrations/` (namespace `DoctrineMigrations`), one class per change |
| Config | `config/packages/doctrine_migrations.yaml` |
| Template for generated classes | `config/doctrine_migrations/migration.php.tpl` (adds the MySQL/MariaDB `abortIf` guard) |
| History table | `doctrine_migration_versions` |
| Boot / upgrade command | `antispam:db:upgrade` (`AntispamBundle\Command\DbUpgradeCommand`, logic in `Services/Database/DatabaseUpgrader`) |
| Baseline | `migrations/Version20261028132604.php` - the full schema at 2.0.0 (master `a76ca5b`), generated against an empty MariaDB 10.6 |

Only MySQL / MariaDB are supported: every migration starts with
`abortIf(!platform instanceof AbstractMySQLPlatform)` (the test suite checks it).
Migrations are **not** wrapped in a transaction (`transactional: false`): MySQL commits
DDL implicitly, so a transaction would protect nothing.

## antispam:db:upgrade

```bash
php bin/console antispam:db:upgrade --dry-run   # state + plan, changes nothing
php bin/console antispam:db:upgrade
```

It looks at the database and picks one of three paths:

| State | How it is detected | What it does |
| --- | --- | --- |
| `fresh` | no table of the entity mapping exists | runs all migrations (the baseline creates the schema) |
| `legacy` | entity tables exist, **no migration recorded** (an install made by the old `schema:update` boot, possibly lagging behind) | 1. `doctrine:schema:update` once - brings the old schema to the current entities, as the old boot did; 2. records every available migration as executed (`doctrine:migrations:version --add --all`); 3. migrate (no-op) |
| `migrated` | at least one migration recorded | runs the pending migrations (`doctrine:migrations:migrate --allow-no-migration`) |

Details that matter for an upgrade:

- The decision is "is any migration recorded", not "does the history table exist": an
  adoption that died after creating `doctrine_migration_versions` but before recording
  the versions is simply adopted again.
- In the `legacy` step 1 every statement is printed. Statements that drop a column are
  tagged `[DROPS DATA]` (the old boot dropped them silently too). `DROP TABLE` of a
  table the entities do not know (another app in the same database, a table of a newer
  release) is **never** run - it is listed as `[skipped, table kept]`.
- Concurrent boots (two `app` replicas) are serialized with a MySQL named lock
  (`GET_LOCK('antispam_db_upgrade')`, `--lock-timeout`, default 600 s).
- After migrating it compares the entities with the database (DROPs ignored). A
  difference means an entity change was merged without a migration: the command warns
  and exits with 2.
- Migrations recorded in the database but not shipped by the image (a newer release
  was deployed before, then an older image) are reported as a warning (exit 2).
  Downgrades are not supported - deploy the newer release again.

Exit codes: `0` up to date, `1` failed (database unreachable, migration error, lock
timeout - the output says which), `2` done with warnings (see above).

### At container start

`docker/entrypoint.sh` runs `doctrine:database:create --if-not-exists` and
`antispam:db:upgrade` when `RUN_MIGRATIONS=true` (default; the `scheduler` service has
it `false`, only `app` upgrades). On failure the entrypoint prints an ERROR banner and
**still starts Apache**, like the old `schema:update || true`: a crash loop would take
down the panel and `/health` too, which are where the problem shows up
(`antispam:doctor` / health check `schema`), and re-running a failed migration in a
restart loop rarely fixes it. `RUN_MIGRATIONS_STRICT=true` makes the container exit
instead (useful with an orchestrator that alerts on restarts, or for a one-off
`docker compose run app true` upgrade step in CI).

Without Docker run `php bin/console antispam:db:upgrade` after every `composer install`
of a new release (see `UPGRADE.md`).

### Checking

```bash
php bin/console antispam:doctor                 # check "schema"
php bin/console doctrine:migrations:status
php bin/console doctrine:migrations:list
```

`antispam:doctor` `schema`: **FAIL** when migrations are pending (also for a legacy
install that was never adopted, e.g. `RUN_MIGRATIONS=false`), **WARN** when all are
executed but the entities still differ from the database (missing migration), OK
otherwise. The health check `schema` (`/health?full=1`) warns on the same difference.

## Adding a migration (developers)

Every entity change (new column, index, table, changed length / nullability) ships with
a migration in the same commit. Nothing applies entity changes automatically any more.

1. **Have a dev database at the previous state.** Usually your local MariaDB with
   `php bin/console antispam:db:upgrade` run on the branch *before* your entity change
   (or a throwaway one:
   `docker run -d --name as-dev-db -e MARIADB_ROOT_PASSWORD=root -e MARIADB_DATABASE=antispam -e MARIADB_USER=antispam -e MARIADB_PASSWORD=antispam -p 33070:3306 mariadb:10.6`,
   then `DATABASE_PORT=33070 php bin/console antispam:db:upgrade`). Use the same
   `DATABASE_SERVER_VERSION` as production (`10.6.0-MariaDB`).
2. **Change the entities**, then generate the diff:
   ```bash
   php bin/console doctrine:migrations:diff --formatted
   ```
   It writes `migrations/VersionYYYYMMDDHHMMSS.php` from the template (with the MySQL
   guard). If it says "No changes detected", the mapping did not change.
3. **Review** the generated SQL:
   - set `getDescription()` (replace the `TODO`);
   - only your change is in it - unrelated statements mean the dev database was not at
     the previous state (fix it and regenerate);
   - a rename shows as DROP + ADD: replace it with `ALTER TABLE ... CHANGE old new ...`
     so the data is kept;
   - a new `NOT NULL` column on an existing table needs a `DEFAULT` (or add it nullable,
     backfill with `UPDATE`, then make it NOT NULL);
   - data changes (`UPDATE`/`INSERT`) are allowed, but note that installs adopted from
     the `legacy` state record all migrations as executed without running them, so a
     data fix must not be the only way a value gets set (the code must cope with
     the default);
   - `down()` should undo `up()`; it is not used by the upgrade path but helps on dev.
4. **Apply and verify** on the dev database:
   ```bash
   php bin/console antispam:db:upgrade      # runs it, then reports any remaining drift
   php bin/console doctrine:schema:validate # "in sync" (or only DROPs of foreign tables)
   vendor/bin/phpunit                       # MigrationsConfigTest checks the MySQL guard
   ```
5. **Commit** the migration together with the entity change. Never edit a migration that
   was released (it already ran on customer databases) - write a new one.

When several branches add migrations in parallel, each one gets its own timestamped
class; they run in version order. Generate each branch's migration after rebasing it on
the branch that already contains the others (otherwise its diff repeats their changes).

### Branches merged without a migration

Entity changes merged without a migration (for example the per-mailbox settings and the
user self-service / 2FA work, developed in parallel with this change) are caught by
`antispam:db:upgrade` (exit 2, "entities still differ") and `antispam:doctor` (`schema`
WARN). To add the missing migration after the merge:

```bash
git checkout master                      # with the merged entity changes
# dev DB at the state of the last release = all existing migrations applied:
DATABASE_PORT=33070 php bin/console antispam:db:upgrade      # exits 2, lists the drift
DATABASE_PORT=33070 php bin/console doctrine:migrations:diff --formatted
# review (step 3 above), then apply and check:
DATABASE_PORT=33070 php bin/console antispam:db:upgrade      # exit 0
git add migrations/ && git commit -m "Migration: per-mailbox settings"
```

One migration per feature keeps the review readable: generate the first after merging
the first branch, commit it, then merge the next branch and repeat.

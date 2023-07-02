
# Notable changes from Vaultwarden Main
* `diesel` (mysql+postgres+sqlite) -> `tokio-postgres` (removed mysql, sqlite)
  * ORMs cause bugs to slip through too often. Postgres (and by extension CockroachDB) are perfect candidates in lieu of others.
* `rocket` -> `axum`
  * Rocket is not production ready. Axum mostly is.
* Env var configuration -> YAML configuration
  * Easier to reason about
* Significantly improved Postgres representation
  * 2FA incomplete system logic now handles concurrent incomplete logins
  * Use indexes where appropriate
  * Using views for authorization
  * Removed the concept of UserOrganization as first class objects (they now are a compound primary key of user and org)

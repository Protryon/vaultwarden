
# Notable changes from Vaultwarden Main
* diesel (mysql+postgres+sqlite) -> tokio-postgres (removed mysql, sqlite)
* rocket -> axum
* env var configuration -> YAML configuration
* made 2FA incomplete system more robust
* significantly improved postgres representation (indexes, UUID not str, etc)
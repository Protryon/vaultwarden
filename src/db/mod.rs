// TODO: CONFIG.database_init_stmts?

use std::time::Duration;

use always_cell::AlwaysCell;
use bb8::{Pool, PooledConnection};
use bb8_postgres::PostgresConnectionManager;
use log::info;
use tokio_postgres::{config::SslMode, Client, Config, NoTls};

use anyhow::Result;

use crate::config::CONFIG;

mod embedded {
    use refinery::embed_migrations;
    embed_migrations!("migrations");
}

mod models;
pub use models::*;

pub type Conn = Client;
pub type ConnOwned = PooledConnection<'static, PostgresConnectionManager<NoTls>>;

pub static DB: AlwaysCell<Pool<PostgresConnectionManager<NoTls>>> = AlwaysCell::new();

pub(super) async fn init() -> Result<()> {
    let mut config = Config::new();
    config
        .host(&CONFIG.db.host)
        .port(CONFIG.db.port)
        .user(&CONFIG.db.username)
        .password(&*CONFIG.db.password)
        .dbname(&CONFIG.db.database)
        .connect_timeout(Duration::from_secs(CONFIG.advanced.database_timeout))
        .ssl_mode(SslMode::Disable);
    let _ = config.connect(NoTls).await?;
    let manager = bb8_postgres::PostgresConnectionManager::new(config, NoTls);
    let pool = bb8::Pool::builder()
        .max_size(CONFIG.advanced.database_max_conns)
        .connection_timeout(Duration::from_secs(CONFIG.advanced.database_timeout))
        .build(manager)
        .await?;

    let mut conn = pool.get().await?;
    embedded::migrations::runner().run_async(&mut *conn).await?;
    info!("finished psql migrations");

    drop(conn);

    AlwaysCell::set(&DB, pool);
    Ok(())
}

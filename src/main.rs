#![forbid(unsafe_code, non_ascii_idents)]
#![deny(
    rust_2018_idioms,
    rust_2021_compatibility,
    noop_method_call,
    trivial_casts,
    trivial_numeric_casts,
    clippy::cast_lossless,
    clippy::clone_on_ref_ptr,
    clippy::equatable_if_let,
    clippy::float_cmp_const,
    clippy::inefficient_to_string,
    clippy::iter_on_empty_collections,
    clippy::iter_on_single_items,
    clippy::linkedlist,
    clippy::macro_use_imports,
    clippy::manual_assert,
    clippy::manual_instant_elapsed,
    clippy::manual_string_new,
    clippy::match_wildcard_for_single_variants,
    clippy::mem_forget,
    clippy::string_add_assign,
    clippy::string_to_string,
    clippy::unnecessary_join,
    clippy::unnecessary_self_imports,
    clippy::unused_async,
    clippy::verbose_file_reads,
    clippy::zero_sized_map_values
)]
// The recursion_limit is mainly triggered by the json!() macro.
// The more key/value pairs there are the more recursion occurs.
// We want to keep this as low as possible, but not higher then 128.
// If you go above 128 it will cause rust-analyzer to fail,
#![recursion_limit = "250"]

use std::{panic, path::Path, process::exit, str::FromStr, thread, time::Duration};

use axol::Result;
use log::{error, info};
use opentelemetry::{runtime::Tokio, sdk::propagation::TraceContextPropagator};
use opentelemetry_otlp::{ExportConfig, Protocol, WithExportConfig};
use tokio::{
    fs::File,
    io::{AsyncBufReadExt, BufReader},
};

#[macro_use]
mod error;
mod api;
mod auth;
mod config;
mod crypto;
mod templates;
#[macro_use]
mod db;
mod events;
mod jobs;
mod mail;
mod push;
mod ratelimit;
mod util;

pub use config::CONFIG;
pub use error::MapResult;
use tracing_subscriber::{layer::SubscriberExt, Registry};
pub use util::is_running_in_docker;

#[tokio::main]
async fn main() {
    launch_info();

    config::load().await.expect("failed to load config");

    let level = log::LevelFilter::from_str(&CONFIG.advanced.log_level).expect("Valid log level");
    init_logging(level).ok();

    if let Some(config) = &CONFIG.opentelemetry {
        let tracer = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(opentelemetry_otlp::new_exporter().tonic().with_export_config(ExportConfig {
                endpoint: config.endpoint.to_string(),
                protocol: Protocol::Grpc,
                timeout: Duration::from_secs_f64(config.timeout_sec),
            }))
            .install_batch(Tokio)
            .expect("tracer init failed");

        let telemetry = tracing_opentelemetry::layer().with_tracer(tracer);

        tracing::subscriber::set_global_default(Registry::default().with(telemetry)).unwrap();
        opentelemetry::global::set_text_map_propagator(TraceContextPropagator::default());
        info!("otel tracing initialized");
    }

    check_data_folder().await;
    check_rsa_keys().await.unwrap_or_else(|e| {
        error!("Error creating keys, exiting...: {e}");
        exit(1);
    });
    check_web_vault();

    create_dir(&CONFIG.folders.icon_cache(), "icon cache").await;
    create_dir(&CONFIG.folders.tmp(), "tmp folder").await;
    create_dir(&CONFIG.folders.sends(), "sends folder").await;
    create_dir(&CONFIG.folders.attachments(), "attachments folder").await;

    db::init().await.expect("database failed to init");
    jobs::schedule_jobs();
    // crate::db::models::TwoFactor::migrate_u2f_to_webauthn(&mut pool.get().await.unwrap()).await.unwrap();

    api::run_api_server().await;
}

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

fn launch_info() {
    println!(
        "\
        /--------------------------------------------------------------------\\\n\
        |                        Starting Vaultwarden                        |"
    );

    println!("|{:^68}|", format!("Version {VERSION}"));

    println!(
        "\
        |--------------------------------------------------------------------|\n\
        | This is an *unofficial* Bitwarden implementation, DO NOT use the   |\n\
        | official channels to report bugs/features, regardless of client.   |\n\
        | Send usage/configuration questions or feature requests to:         |\n\
        |   https://github.com/dani-garcia/vaultwarden/discussions or        |\n\
        |   https://vaultwarden.discourse.group/                             |\n\
        | Report suspected bugs/issues in the software itself at:            |\n\
        |   https://github.com/dani-garcia/vaultwarden/issues/new            |\n\
        \\--------------------------------------------------------------------/\n"
    );
}

fn init_logging(level: log::LevelFilter) -> Result<(), fern::InitError> {
    // Depending on the main log level we either want to disable or enable logging for trust-dns.
    // Else if there are timeouts it will clutter the logs since trust-dns uses warn for this.
    let trust_dns_level = if level >= log::LevelFilter::Debug {
        level
    } else {
        log::LevelFilter::Off
    };

    let mut logger = fern::Dispatch::new()
        .level(level)
        // Hide failed to close stream messages
        .level_for("hyper::server", log::LevelFilter::Warn)
        // Silence Rocket logs
        .level_for("hyper::proto", log::LevelFilter::Off)
        .level_for("hyper::client", log::LevelFilter::Off)
        // Prevent cookie_store logs
        .level_for("cookie_store", log::LevelFilter::Off)
        // Variable level for trust-dns used by reqwest
        .level_for("trust_dns_resolver::name_server::name_server", trust_dns_level)
        .level_for("trust_dns_proto::xfer", trust_dns_level)
        .chain(std::io::stdout());

    // Enable smtp debug logging only specifically for smtp when need.
    // This can contain sensitive information we do not want in the default debug/trace logging.
    if CONFIG.smtp.as_ref().map(|x| x.debug).unwrap_or_default() {
        println!(
            "[WARNING] SMTP Debugging is enabled (SMTP_DEBUG=true). Sensitive information could be disclosed via logs!\n\
             [WARNING] Only enable SMTP_DEBUG during troubleshooting!\n"
        );
        logger = logger.level_for("lettre::transport::smtp", log::LevelFilter::Debug)
    } else {
        logger = logger.level_for("lettre::transport::smtp", log::LevelFilter::Off)
    }

    logger = logger.format(|out, message, record| {
        out.finish(format_args!("[{}][{}][{}] {}", chrono::Local::now().to_rfc3339(), record.target(), record.level(), message))
    });

    logger.apply()?;

    // Catch panics and log them instead of default output to StdErr
    panic::set_hook(Box::new(|info| {
        let thread = thread::current();
        let thread = thread.name().unwrap_or("unnamed");

        let msg = match info.payload().downcast_ref::<&'static str>() {
            Some(s) => *s,
            None => match info.payload().downcast_ref::<String>() {
                Some(s) => &**s,
                None => "Box<Any>",
            },
        };

        let backtrace = std::backtrace::Backtrace::force_capture();

        match info.location() {
            Some(location) => {
                error!(
                    target: "panic", "thread '{}' panicked at '{}': {}:{}\n{:}",
                    thread,
                    msg,
                    location.file(),
                    location.line(),
                    backtrace
                );
            }
            None => error!(
                target: "panic",
                "thread '{}' panicked at '{}'\n{:}",
                thread,
                msg,
                backtrace
            ),
        }
    }));

    Ok(())
}

async fn create_dir(path: &Path, description: &str) {
    // Try to create the specified dir, if it doesn't already exist.
    let err_msg = format!("Error creating {description} directory '{}'", path.display());
    tokio::fs::create_dir_all(path).await.expect(&err_msg);
}

async fn check_data_folder() {
    let data_folder = &CONFIG.folders.data;
    if !data_folder.exists() {
        error!("Data folder '{}' doesn't exist.", data_folder.display());
        if is_running_in_docker() {
            error!("Verify that your data volume is mounted at the correct location.");
        } else {
            error!("Create the data folder and try again.");
        }
        exit(1);
    }
    if !data_folder.is_dir() {
        error!("Data folder '{}' is not a directory.", data_folder.display());
        exit(1);
    }

    if is_running_in_docker() && std::env::var("I_REALLY_WANT_VOLATILE_STORAGE").is_err() && !docker_data_folder_is_persistent(data_folder).await {
        error!(
            "No persistent volume!\n\
            ########################################################################################\n\
            # It looks like you did not configure a persistent volume!                             #\n\
            # This will result in permanent data loss when the container is removed or updated!    #\n\
            # If you really want to use volatile storage set `I_REALLY_WANT_VOLATILE_STORAGE=true` #\n\
            ########################################################################################\n"
        );
        exit(1);
    }
}

/// Detect when using Docker or Podman the DATA_FOLDER is either a bind-mount or a volume created manually.
/// If not created manually, then the data will not be persistent.
/// A none persistent volume in either Docker or Podman is represented by a 64 alphanumerical string.
/// If we detect this string, we will alert about not having a persistent self defined volume.
/// This probably means that someone forgot to add `-v /path/to/vaultwarden_data/:/data`
async fn docker_data_folder_is_persistent(data_folder: &Path) -> bool {
    if let Ok(mountinfo) = File::open("/proc/self/mountinfo").await {
        // Since there can only be one mountpoint to the DATA_FOLDER
        // We do a basic check for this mountpoint surrounded by a space.
        let data_folder_match = if data_folder.is_absolute() {
            format!(" {} ", data_folder.display())
        } else {
            format!(" /{} ", data_folder.display())
        };
        let mut lines = BufReader::new(mountinfo).lines();
        while let Some(line) = lines.next_line().await.unwrap_or_default() {
            // Only execute a regex check if we find the base match
            if line.contains(&data_folder_match) {
                let re = regex::Regex::new(r"/volumes/[a-z0-9]{64}/_data /").unwrap();
                if re.is_match(&line) {
                    return false;
                }
                // If we did found a match for the mountpoint, but not the regex, then still stop searching.
                break;
            }
        }
    }
    // In all other cases, just assume a true.
    // This is just an informative check to try and prevent data loss.
    true
}

async fn check_rsa_keys() -> anyhow::Result<()> {
    // If the RSA keys don't exist, try to create them
    let priv_path = CONFIG.private_rsa_key();
    let pub_path = CONFIG.public_rsa_key();

    if !util::file_exists(&priv_path).await? {
        let rsa_key = openssl::rsa::Rsa::generate(2048)?;

        let priv_key = rsa_key.private_key_to_pem()?;
        crate::util::write_file(&priv_path, &priv_key).await?;
        info!("Private key created correctly.");
    }

    if !util::file_exists(&pub_path).await? {
        let rsa_key = openssl::rsa::Rsa::private_key_from_pem(&std::fs::read(&priv_path)?)?;

        let pub_key = rsa_key.public_key_to_pem()?;
        crate::util::write_file(&pub_path, &pub_key).await?;
        info!("Public key created correctly.");
    }

    auth::load_keys();
    Ok(())
}

fn check_web_vault() {
    if !CONFIG.settings.web_vault_enabled {
        return;
    }

    let index_path = CONFIG.folders.web_vault().join("index.html");

    if !index_path.exists() {
        error!("Web vault is not found at '{}'. To install it, please follow the steps in: ", CONFIG.folders.web_vault().display());
        error!("https://github.com/dani-garcia/vaultwarden/wiki/Building-binary#install-the-web-vault");
        error!("You can also set the config value 'web_vault_enabled=false' to disable it");
        exit(1);
    }
}

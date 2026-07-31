use std::sync::LazyLock;

use axol::{Error, Result};
use handlebars::{Context, DirectorySourceOptions, Handlebars, Helper, HelperResult, Output, RenderContext, RenderErrorReason, Renderable};
use log::warn;
use serde_json::json;

use crate::CONFIG;

pub fn render_template<T: serde::ser::Serialize>(name: &str, data: &T) -> Result<String> {
    if CONFIG.advanced.reload_templates {
        warn!("RELOADING TEMPLATES");
        let hb = load_templates(CONFIG.folders.templates());
        hb.render(name, data).map_err(Error::internal)
    } else {
        TEMPLATES.render(name, data).map_err(Error::internal)
    }
}

lazy_static::lazy_static! {
    static ref TEMPLATES: Handlebars<'static> = load_templates(CONFIG.folders.templates());
}

fn load_templates<P>(path: P) -> Handlebars<'static>
where
    P: AsRef<std::path::Path>,
{
    let mut hb = Handlebars::new();
    // Error on missing params
    hb.set_strict_mode(true);
    // Register helpers
    hb.register_helper("case", Box::new(case_helper));
    hb.register_helper("jsesc", Box::new(js_escape_helper));
    hb.register_helper("to_json", Box::new(to_json));
    hb.register_helper("webver", Box::new(webver));

    macro_rules! reg {
        ($name:expr) => {{
            let template = include_str!(concat!("static/templates/", $name, ".hbs"));
            hb.register_template_string($name, template).unwrap();
        }};
        ($name:expr, $ext:expr) => {{
            reg!($name);
            reg!(concat!($name, $ext));
        }};
    }

    // First register default templates here
    reg!("email/email_header");
    reg!("email/email_footer");
    reg!("email/email_footer_text");

    reg!("email/admin_reset_password", ".html");
    reg!("email/change_email", ".html");
    reg!("email/delete_account", ".html");
    reg!("email/emergency_access_invite_accepted", ".html");
    reg!("email/emergency_access_invite_confirmed", ".html");
    reg!("email/emergency_access_recovery_approved", ".html");
    reg!("email/emergency_access_recovery_initiated", ".html");
    reg!("email/emergency_access_recovery_rejected", ".html");
    reg!("email/emergency_access_recovery_reminder", ".html");
    reg!("email/emergency_access_recovery_timed_out", ".html");
    reg!("email/incomplete_2fa_login", ".html");
    reg!("email/invite_accepted", ".html");
    reg!("email/invite_confirmed", ".html");
    reg!("email/new_device_logged_in", ".html");
    reg!("email/pw_hint_none", ".html");
    reg!("email/pw_hint_some", ".html");
    reg!("email/send_2fa_removed_from_org", ".html");
    reg!("email/send_single_org_removed_from_org", ".html");
    reg!("email/send_org_invite", ".html");
    reg!("email/send_emergency_access_invite", ".html");
    reg!("email/set_password", ".html");
    reg!("email/twofactor_email", ".html");
    reg!("email/verify_email", ".html");
    reg!("email/welcome", ".html");
    reg!("email/welcome_must_verify", ".html");
    reg!("email/smtp_test", ".html");

    reg!("admin/base");
    reg!("admin/login");
    reg!("admin/settings");
    reg!("admin/users");
    reg!("admin/organizations");
    reg!("admin/diagnostics");

    reg!("scss/vaultwarden.scss");
    reg!("scss/user.vaultwarden.scss");

    reg!("404");

    // And then load user templates to overwrite the defaults
    // Use .hbs extension for the files
    // Templates get registered with their relative name
    let mut dir_opts = DirectorySourceOptions::default();
    dir_opts.tpl_extension = ".hbs".to_owned();
    hb.register_templates_directory(path, dir_opts).unwrap();

    hb
}

fn case_helper<'reg, 'rc>(
    h: &Helper<'rc>,
    r: &'reg Handlebars<'_>,
    ctx: &'rc Context,
    rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let param = h.param(0).ok_or_else(|| RenderErrorReason::Other(String::from("Param not found for helper \"case\"")))?;
    let value = param.value().clone();

    if h.params().iter().skip(1).any(|x| x.value() == &value) {
        h.template().map(|t| t.render(r, ctx, rc, out)).unwrap_or_else(|| Ok(()))
    } else {
        Ok(())
    }
}

fn js_escape_helper<'reg, 'rc>(
    h: &Helper<'rc>,
    _r: &'reg Handlebars<'_>,
    _ctx: &'rc Context,
    _rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let param = h.param(0).ok_or_else(|| RenderErrorReason::Other(String::from("Param not found for helper \"jsesc\"")))?;

    let no_quote = h.param(1).is_some();

    let value = param.value().as_str().ok_or_else(|| RenderErrorReason::Other(String::from("Param for helper \"jsesc\" is not a String")))?;

    let mut escaped_value = value.replace('\\', "").replace('\'', "\\x22").replace('\"', "\\x27");
    if !no_quote {
        escaped_value = format!("&quot;{escaped_value}&quot;");
    }

    out.write(&escaped_value)?;
    Ok(())
}

fn to_json<'reg, 'rc>(h: &Helper<'rc>, _r: &'reg Handlebars<'_>, _ctx: &'rc Context, _rc: &mut RenderContext<'reg, 'rc>, out: &mut dyn Output) -> HelperResult {
    let param = h.param(0).ok_or_else(|| RenderErrorReason::Other(String::from("Expected 1 parameter for \"to_json\"")))?.value();
    let json = serde_json::to_string(param).map_err(|e| RenderErrorReason::Other(format!("Can't serialize parameter to JSON: {e}")))?;
    out.write(&json)?;
    Ok(())
}

/// The installed web-vault's version, as used by the `webver` helper to gate
/// the parts of the customization stylesheet whose selectors are version
/// specific. Read once from the version file the web-vault image ships.
static WEB_VAULT_VERSION: LazyLock<semver::Version> = LazyLock::new(|| {
    // Oldest version the stylesheet has selectors for, used when the file is
    // missing or unparseable.
    let fallback = || semver::Version::new(2024, 6, 2);

    let dir = CONFIG.folders.web_vault();
    let Some(raw) = ["vw-version.json", "version.json"].into_iter().find_map(|file| std::fs::read_to_string(dir.join(file)).ok()) else {
        warn!("No web-vault version file found, assuming v{}", fallback());
        return fallback();
    };
    let version = serde_json::from_str::<serde_json::Value>(&raw)
        .ok()
        .and_then(|json| json.get("version").and_then(|v| v.as_str()).map(ToOwned::to_owned))
        .unwrap_or(raw);

    let re = regex::Regex::new(r"(\d{4})\.(\d{1,2})\.(\d{1,2})").unwrap();
    re.captures(&version).and_then(|c| semver::Version::parse(&format!("{}.{}.{}", &c[1], &c[2], &c[3])).ok()).unwrap_or_else(|| {
        warn!("Could not parse web-vault version {version:?}, assuming v{}", fallback());
        fallback()
    })
});

handlebars::handlebars_helper!(webver: |web_vault_version: String|
    semver::VersionReq::parse(&web_vault_version).expect("invalid web-vault version comparison in template").matches(&WEB_VAULT_VERSION)
);

/// Render the web-vault customization stylesheet: the SCSS template hides the
/// features this server doesn't offer, and is then compiled to CSS.
pub fn render_vaultwarden_css() -> Result<String> {
    let mut options = json!({
        "emergency_access_allowed": CONFIG.settings.emergency_access_allowed,
        "load_user_scss": true,
        "mail_2fa_enabled": CONFIG.email_2fa.is_some() && CONFIG.mail_enabled(),
        "mail_enabled": CONFIG.mail_enabled(),
        "sends_allowed": CONFIG.settings.sends_allowed,
        "remember_2fa_disabled": CONFIG.advanced.disable_2fa_remember,
        "password_hints_allowed": CONFIG.settings.password_hints_allowed,
        "signup_disabled": CONFIG.is_signup_disabled(),
        "sso_enabled": CONFIG.sso.is_some(),
        "sso_only": CONFIG.sso.as_ref().is_some_and(|sso| sso.force_sso),
        "webauthn_2fa_supported": CONFIG.settings.public.domain().is_some(),
        "yubico_enabled": CONFIG.yubico.is_some(),
    });

    match compile_scss(&options) {
        Ok(css) => Ok(css),
        // A broken user stylesheet shouldn't take the whole web-vault's styling
        // with it, so drop it and render what we ship.
        Err(e) => {
            warn!("Rendering scss/user.vaultwarden.scss failed, ignoring it: {e:?}");
            options["load_user_scss"] = json!(false);
            compile_scss(&options)
        }
    }
}

fn compile_scss(options: &serde_json::Value) -> Result<String> {
    let scss = render_template("scss/vaultwarden.scss", options)?;
    grass_compiler::from_string(scss, &grass_compiler::Options::default().style(grass_compiler::OutputStyle::Compressed)).map_err(Error::internal)
}

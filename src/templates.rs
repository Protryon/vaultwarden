use axol::{Error, Result};
use handlebars::{Context, Handlebars, Helper, HelperResult, Output, RenderContext, RenderError, Renderable};
use log::warn;

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

    reg!("404");

    // And then load user templates to overwrite the defaults
    // Use .hbs extension for the files
    // Templates get registered with their relative name
    hb.register_templates_directory(".hbs", path).unwrap();

    hb
}

fn case_helper<'reg, 'rc>(
    h: &Helper<'reg, 'rc>,
    r: &'reg Handlebars<'_>,
    ctx: &'rc Context,
    rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let param = h.param(0).ok_or_else(|| RenderError::new("Param not found for helper \"case\""))?;
    let value = param.value().clone();

    if h.params().iter().skip(1).any(|x| x.value() == &value) {
        h.template().map(|t| t.render(r, ctx, rc, out)).unwrap_or_else(|| Ok(()))
    } else {
        Ok(())
    }
}

fn js_escape_helper<'reg, 'rc>(
    h: &Helper<'reg, 'rc>,
    _r: &'reg Handlebars<'_>,
    _ctx: &'rc Context,
    _rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let param = h.param(0).ok_or_else(|| RenderError::new("Param not found for helper \"jsesc\""))?;

    let no_quote = h.param(1).is_some();

    let value = param.value().as_str().ok_or_else(|| RenderError::new("Param for helper \"jsesc\" is not a String"))?;

    let mut escaped_value = value.replace('\\', "").replace('\'', "\\x22").replace('\"', "\\x27");
    if !no_quote {
        escaped_value = format!("&quot;{escaped_value}&quot;");
    }

    out.write(&escaped_value)?;
    Ok(())
}

fn to_json<'reg, 'rc>(
    h: &Helper<'reg, 'rc>,
    _r: &'reg Handlebars<'_>,
    _ctx: &'rc Context,
    _rc: &mut RenderContext<'reg, 'rc>,
    out: &mut dyn Output,
) -> HelperResult {
    let param = h.param(0).ok_or_else(|| RenderError::new("Expected 1 parameter for \"to_json\""))?.value();
    let json = serde_json::to_string(param).map_err(|e| RenderError::new(format!("Can't serialize parameter to JSON: {e}")))?;
    out.write(&json)?;
    Ok(())
}

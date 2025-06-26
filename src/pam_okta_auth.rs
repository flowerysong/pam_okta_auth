/* This file is part of pam_okta_auth and is distributed under the
 * terms of the MIT license.
 * See COPYING.
 */

#[rustfmt::skip]
use pamsm::{
    LogLvl,
    Pam,
    PamError,
    PamFlags,
    PamLibExt,
    PamMsgStyle,
    PamServiceModule,
    pam_module,
};

struct PamOkta;

#[derive(serde::Deserialize)]
struct OktaConfig {
    host: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    bypass_groups: toml::value::Array,
}

fn check_bypass_groups(pamh: &Pam, conf: &OktaConfig, username: &str) -> Option<PamError> {
    if conf.bypass_groups.is_empty() {
        return None;
    }

    match uzers::get_user_by_name(username) {
        Some(user) => {
            for group1 in user.groups().unwrap() {
                let g1 = group1.name().to_str().unwrap_or("");
                for group2 in &conf.bypass_groups {
                    let g2 = group2.as_str().unwrap_or("");
                    if g1 == g2 {
                        log_info(pamh, &format!("User is in bypass group {g2}"));
                        return Some(PamError::SUCCESS);
                    }
                }
            }
        }
        None => return Some(PamError::USER_UNKNOWN),
    }
    None
}

fn log_error(pamh: &Pam, error: &dyn std::error::Error) -> PamError {
    match pamh.syslog(LogLvl::NOTICE, &format!("Error: {}", error)) {
        Ok(_) => {}
        Err(e) => return e,
    }

    PamError::AUTHINFO_UNAVAIL
}

fn log_info(pamh: &Pam, msg: &str) {
    let _ = pamh.syslog(LogLvl::INFO, msg);
}

fn factor_otp(pamh: &Pam, conf: &OktaConfig, username: &str, otp: &str) -> PamError {
    log_info(
        pamh,
        &format!("Attempting OTP authentication for {username}"),
    );

    let url = format!("https://{}/oauth2/v1/token", conf.host);
    let form_data = [
        ("client_id", conf.client_id.as_str()),
        ("client_secret", conf.client_secret.as_str()),
        ("grant_type", "urn:okta:params:oauth:grant-type:otp"),
        ("scope", "openid"),
        ("login_hint", username),
        ("otp", otp),
    ];
    match ureq::post(&url).send_form(form_data) {
        Ok(_) => PamError::SUCCESS,
        Err(e) => log_error(pamh, &e),
    }
}

fn factor_password(pamh: &Pam, conf: &OktaConfig, username: &str, password: &str) -> PamError {
    log_info(
        pamh,
        &format!("Attempting password authentication for {username}"),
    );
    let url = format!("https://{}/oauth2/v1/token", conf.host);
    let form_data = [
        ("client_id", conf.client_id.as_str()),
        ("client_secret", conf.client_secret.as_str()),
        ("grant_type", "password"),
        ("scope", "openid"),
        ("username", username),
        ("password", password),
    ];
    match ureq::post(&url).send_form(form_data) {
        Ok(_) => PamError::SUCCESS,
        Err(e) => log_error(pamh, &e),
    }
}

fn factor_push(pamh: &Pam, conf: &OktaConfig, username: &str) -> PamError {
    log_info(
        pamh,
        &format!("Attempting push authentication for {username}"),
    );

    let push_url = format!("https://{}/oauth2/v1/oob-authenticate", conf.host);
    let form_data = [
        ("client_id", conf.client_id.as_str()),
        ("client_secret", conf.client_secret.as_str()),
        ("channel_hint", "push"),
        ("login_hint", username),
    ];

    let resp_json: serde_json::Value = match ureq::post(&push_url).send_form(form_data) {
        Ok(mut resp) => match resp.body_mut().read_json() {
            Ok(res) => res,
            Err(e) => return log_error(pamh, &e),
        },
        Err(e) => return log_error(pamh, &e),
    };

    log_info(pamh, "Successfully initiated push");

    let now = std::time::Instant::now();
    let token_url = format!("https://{}/oauth2/v1/token", conf.host);

    let form_data = [
        ("client_id", conf.client_id.as_str()),
        ("client_secret", conf.client_secret.as_str()),
        ("grant_type", "urn:okta:params:oauth:grant-type:oob"),
        ("scope", "openid"),
        ("oob_code", resp_json["oob_code"].as_str().unwrap_or("")),
    ];

    let timeout = resp_json["expires_in"].as_u64().unwrap_or(0);
    let interval = std::time::Duration::from_secs(resp_json["interval"].as_u64().unwrap_or(10));

    while now.elapsed().as_secs() <= timeout {
        std::thread::sleep(interval);
        if ureq::post(&token_url).send_form(form_data).is_ok() {
            return PamError::SUCCESS;
        }
    }

    log_info(pamh, "Timed out waiting for acknowledgment");
    PamError::AUTHINFO_UNAVAIL
}

impl PamServiceModule for PamOkta {
    fn authenticate(pamh: Pam, _: PamFlags, args: Vec<String>) -> PamError {
        let username = match pamh.get_user(None) {
            Ok(Some(user)) => user.to_str().unwrap_or(""),
            Ok(None) => return PamError::USER_UNKNOWN,
            Err(e) => return e,
        };

        log_info(&pamh, &format!("Authentication attempt for {username}"));

        let mut conf_path = String::from("/etc/security/pam_okta_auth.toml");
        let mut password_auth = false;
        let mut try_first_pass = false;
        let mut use_first_pass = false;

        for arg in args {
            match arg.split_once("=") {
                Some((k, v)) => match k {
                    "config_file" => {
                        conf_path = String::from(v);
                    }
                    _ => log_info(&pamh, &format!("Unknown PAM argument: {arg}")),
                },
                None => match arg.as_str() {
                    "password_auth" => password_auth = true,
                    "try_first_pass" => try_first_pass = true,
                    "use_first_pass" => use_first_pass = true,
                    _ => log_info(&pamh, &format!("Unknown PAM argument: {arg}")),
                },
            }
        }

        let conf_file = match std::fs::read_to_string(std::path::Path::new(&conf_path)) {
            Ok(f) => f,
            Err(e) => return log_error(&pamh, &e),
        };

        let conf: OktaConfig = toml::from_str(&conf_file).unwrap();

        if password_auth {
            if try_first_pass || use_first_pass {
                let password = match pamh.get_cached_authtok() {
                    Ok(Some(pass)) => pass.to_str().unwrap_or(""),
                    Ok(_) => "",
                    Err(e) => return e,
                };
                if factor_password(&pamh, &conf, username, password) == PamError::SUCCESS {
                    password_auth = false;
                } else if use_first_pass {
                    return PamError::AUTH_ERR;
                }
            }
            if password_auth {
                let password =
                    match pamh.conv(Some("Okta password: "), PamMsgStyle::PROMPT_ECHO_OFF) {
                        Ok(Some(pass)) => pass.to_str().unwrap_or(""),
                        Ok(_) => "",
                        Err(e) => return e,
                    };
                let res = factor_password(&pamh, &conf, username, password);
                if res != PamError::SUCCESS {
                    return res;
                }
            }
        }

        if let Some(res) = check_bypass_groups(&pamh, &conf, username) {
            return res;
        }

        match pamh.conv(Some(&format!("\nOkta authentication for {username}\n\nPasscode (leave blank to initiate a push): ")), PamMsgStyle::PROMPT_ECHO_ON) {
            Ok(Some(otp)) if !otp.to_str().unwrap_or("").is_empty() =>
                factor_otp(&pamh, &conf, username, otp.to_str().unwrap_or("")),
            Ok(_) => factor_push(&pamh, &conf, username),
            Err(e) => e,
        }
    }

    // The defaults return SERVICE_ERR, so we need to override most of them.
    fn open_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
    fn close_session(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
    fn setcred(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
    fn acct_mgmt(_: Pam, _: PamFlags, _: Vec<String>) -> PamError {
        PamError::SUCCESS
    }
}

pam_module!(PamOkta);

/* This file is part of pam_okta_auth and is distributed under the
 * terms of the MIT license.
 * See COPYING.
 */

use std::os::unix::fs::PermissionsExt;

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
    #[serde(default)]
    http_proxy: String,
    #[serde(default)]
    debug: bool,
}

struct OktaHandle<'a> {
    pamh: &'a Pam,
    conf: OktaConfig,
    agent: ureq::Agent,
}

fn ureq_config_base() -> ureq::config::ConfigBuilder<ureq::typestate::AgentScope> {
    ureq::Agent::config_builder().http_status_as_error(false)
}

impl OktaHandle<'_> {
    fn log_error(&self, msg: &str) {
        let _ = self.pamh.syslog(LogLvl::NOTICE, msg);
    }

    fn log_info(&self, msg: &str) {
        let _ = self.pamh.syslog(LogLvl::INFO, msg);
    }

    fn log_debug(&self, msg: &str) {
        if self.conf.debug {
            self.log_info(msg);
        }
    }

    fn send_error(&self, msg: &str) {
        self.log_error(msg);
        let _ = self.pamh.conv(Some(msg), PamMsgStyle::ERROR_MSG);
    }

    fn send_info(&self, msg: &str) {
        self.log_info(msg);
        let _ = self.pamh.conv(Some(msg), PamMsgStyle::TEXT_INFO);
    }

    fn check_bypass_groups(&self, username: &str) -> Option<PamError> {
        if self.conf.bypass_groups.is_empty() {
            return None;
        }

        match uzers::get_user_by_name(username) {
            Some(user) => {
                for group1 in user.groups().unwrap() {
                    let g1 = group1.name().to_str().unwrap_or("");
                    for group2 in &self.conf.bypass_groups {
                        let g2 = group2.as_str().unwrap_or("");
                        if g1 == g2 {
                            self.log_info(&format!("User is in bypass group {g2}"));
                            return Some(PamError::SUCCESS);
                        }
                    }
                }
            }
            None => return Some(PamError::USER_UNKNOWN),
        }
        None
    }

    fn configure_agent(&mut self) {
        if !self.conf.http_proxy.is_empty() {
            let proxy = ureq::Proxy::new(&self.conf.http_proxy);
            if proxy.is_ok() {
                self.agent = ureq_config_base()
                    .proxy(Some(proxy.unwrap()))
                    .build()
                    .into();
            } else {
                self.log_info(&format!(
                    "Ignoring invalid HTTP proxy: {}",
                    self.conf.http_proxy
                ));
            }
        }
    }

    fn factor_otp(&self, username: &str, otp: &str) -> PamError {
        self.log_info(&format!("Attempting OTP authentication for {username}"));

        let url = format!("https://{}/oauth2/v1/token", self.conf.host);
        let form_data = [
            ("client_id", self.conf.client_id.as_str()),
            ("client_secret", self.conf.client_secret.as_str()),
            ("grant_type", "urn:okta:params:oauth:grant-type:otp"),
            ("scope", "openid"),
            ("login_hint", username),
            ("otp", otp),
        ];
        match self.agent.post(&url).send_form(form_data) {
            Ok(resp) if resp.status().is_success() => {
                self.send_info("OTP authentication succeeded");
                PamError::SUCCESS
            }
            Ok(mut resp) => {
                self.log_error(&format!("HTTP {}", resp.status()));
                self.log_debug(&resp.body_mut().read_to_string().unwrap_or_default());
                PamError::AUTH_ERR
            }
            Err(e) => {
                self.log_error(&e.to_string());
                self.send_error("OTP authentication failed");
                PamError::AUTH_ERR
            }
        }
    }

    fn factor_password(&self, username: &str, password: &str) -> PamError {
        self.log_info(&format!(
            "Attempting password authentication for {username}"
        ));
        let url = format!("https://{}/oauth2/v1/token", self.conf.host);
        let form_data = [
            ("client_id", self.conf.client_id.as_str()),
            ("client_secret", self.conf.client_secret.as_str()),
            ("grant_type", "password"),
            ("scope", "openid"),
            ("username", username),
            ("password", password),
        ];
        match self.agent.post(&url).send_form(form_data) {
            Ok(resp) if resp.status().is_success() => {
                self.send_info("Password authentication succeeded");
                PamError::SUCCESS
            }
            Ok(mut resp) => {
                self.log_error(&format!("HTTP {}", resp.status()));
                self.log_debug(&resp.body_mut().read_to_string().unwrap_or_default());
                PamError::AUTH_ERR
            }
            Err(e) => {
                self.send_error("Password authentication failed");
                self.log_error(&e.to_string());
                PamError::AUTH_ERR
            }
        }
    }

    fn factor_push(&self, username: &str) -> PamError {
        self.log_info(&format!("Attempting push authentication for {username}"));

        let push_url = format!("https://{}/oauth2/v1/oob-authenticate", self.conf.host);
        let form_data = [
            ("client_id", self.conf.client_id.as_str()),
            ("client_secret", self.conf.client_secret.as_str()),
            ("channel_hint", "push"),
            ("login_hint", username),
        ];

        let resp_json: serde_json::Value = match self.agent.post(&push_url).send_form(form_data) {
            Ok(mut resp) if resp.status().is_success() => match resp.body_mut().read_json() {
                Ok(res) => res,
                Err(e) => {
                    self.log_error(&e.to_string());
                    return PamError::AUTHINFO_UNAVAIL;
                }
            },
            Ok(mut resp) => {
                self.log_error(&format!("HTTP {}", resp.status()));
                self.log_debug(&resp.body_mut().read_to_string().unwrap_or_default());
                return PamError::AUTH_ERR;
            }
            Err(e) => {
                self.log_error(&e.to_string());
                return PamError::AUTH_ERR;
            }
        };

        self.send_info("Successfully initiated Okta push");

        let now = std::time::Instant::now();
        let token_url = format!("https://{}/oauth2/v1/token", self.conf.host);

        let form_data = [
            ("client_id", self.conf.client_id.as_str()),
            ("client_secret", self.conf.client_secret.as_str()),
            ("grant_type", "urn:okta:params:oauth:grant-type:oob"),
            ("scope", "openid"),
            ("oob_code", resp_json["oob_code"].as_str().unwrap_or("")),
        ];

        let timeout = resp_json["expires_in"].as_u64().unwrap_or(0);
        let interval = std::time::Duration::from_secs(resp_json["interval"].as_u64().unwrap_or(10));

        while now.elapsed().as_secs() <= timeout {
            std::thread::sleep(interval);

            let resp_json: serde_json::Value =
                match self.agent.post(&token_url).send_form(form_data.clone()) {
                    Ok(resp) if resp.status().is_success() => {
                        self.send_info("Push acknowledged");
                        return PamError::SUCCESS;
                    }
                    Ok(mut resp) => {
                        self.log_debug(&format!("HTTP {}", resp.status()));
                        self.log_debug(&resp.body_mut().read_to_string().unwrap_or_default());
                        match resp.body_mut().read_json() {
                            Ok(res) => res,
                            Err(_) => {
                                continue;
                            }
                        }
                    }
                    Err(_) => {
                        continue;
                    }
                };

            if resp_json["error"].as_str().unwrap_or("") == "invalid_grant" {
                self.send_error(&format!(
                    "Push failed: {}",
                    resp_json["error_description"].as_str().unwrap_or("")
                ));
                return PamError::AUTH_ERR;
            };
        }

        self.send_error("Timed out waiting for acknowledgment");
        PamError::AUTHINFO_UNAVAIL
    }
}

impl PamServiceModule for PamOkta {
    fn authenticate(pamh: Pam, _: PamFlags, args: Vec<String>) -> PamError {
        let username = match pamh.get_user(None) {
            Ok(Some(user)) => user.to_str().unwrap_or(""),
            Ok(None) => return PamError::USER_UNKNOWN,
            Err(e) => return e,
        };

        let mut oh = OktaHandle {
            pamh: &pamh,
            conf: OktaConfig {
                host: String::from(""),
                client_id: String::from(""),
                client_secret: String::from(""),
                bypass_groups: toml::value::Array::new(),
                http_proxy: String::from(""),
                debug: false,
            },
            agent: ureq_config_base().build().into(),
        };

        oh.log_info(&format!("Authentication attempt for {username}"));

        let mut conf_path = String::from("/etc/security/pam_okta_auth.toml");
        let mut autopush = false;
        let mut password_auth = false;
        let mut try_first_pass = false;
        let mut use_first_pass = false;

        for arg in args {
            match arg.split_once("=") {
                Some((k, v)) => match k {
                    "config_file" => {
                        conf_path = String::from(v);
                    }
                    _ => oh.log_info(&format!("Unknown PAM argument: {arg}")),
                },
                None => match arg.as_str() {
                    "autopush" => autopush = true,
                    "password_auth" => password_auth = true,
                    "try_first_pass" => try_first_pass = true,
                    "use_first_pass" => use_first_pass = true,
                    _ => oh.log_info(&format!("Unknown PAM argument: {arg}")),
                },
            }
        }

        let conf_path = std::path::Path::new(&conf_path);
        match conf_path.metadata() {
            Ok(stat) if stat.permissions().mode() & 0o007 != 0o000 => {
                oh.send_error("pam_okta_auth configuration is unusable: unacceptable permissions");
                return PamError::SERVICE_ERR;
            }
            Ok(_) => {}
            Err(e) => {
                oh.send_error(&format!("pam_okta_auth configuration is unusable: {e}"));
                return PamError::SERVICE_ERR;
            }
        }

        let conf_file = match std::fs::read_to_string(conf_path) {
            Ok(f) => f,
            Err(e) => {
                oh.send_error(&format!("pam_okta_auth configuration is unusable: {e}"));
                return PamError::SERVICE_ERR;
            }
        };

        oh.conf = toml::from_str(&conf_file).unwrap();
        oh.configure_agent();

        if password_auth {
            if try_first_pass || use_first_pass {
                let password = match pamh.get_cached_authtok() {
                    Ok(Some(pass)) => pass.to_str().unwrap_or(""),
                    Ok(_) => "",
                    Err(e) => return e,
                };
                if oh.factor_password(username, password) == PamError::SUCCESS {
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
                let res = oh.factor_password(username, password);
                if res != PamError::SUCCESS {
                    return res;
                }
            }
        }

        if let Some(res) = oh.check_bypass_groups(username) {
            return res;
        }

        if autopush {
            return oh.factor_push(username);
        }

        match pamh.conv(
            Some("Okta passcode (leave blank to initiate a push): "),
            PamMsgStyle::PROMPT_ECHO_ON,
        ) {
            Ok(Some(otp)) if !otp.to_str().unwrap_or("").is_empty() => {
                oh.factor_otp(username, otp.to_str().unwrap_or(""))
            }
            Ok(_) => oh.factor_push(username),
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

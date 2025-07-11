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
    mfa_token: Option<String>,
}

fn ureq_config_base() -> ureq::config::ConfigBuilder<ureq::typestate::AgentScope> {
    ureq::Agent::config_builder()
        .user_agent(format!("pam_okta_auth/{}", env!("CARGO_PKG_VERSION")))
        .http_status_as_error(false)
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
                for group1 in user.groups().unwrap_or_default() {
                    let g1 = group1.name().to_str().unwrap_or_default();
                    for group2 in &self.conf.bypass_groups {
                        let g2 = group2.as_str().unwrap_or_default();
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
            if let Ok(proxy_val) = proxy {
                self.agent = ureq_config_base().proxy(Some(proxy_val)).build().into();
            } else {
                self.log_info(&format!(
                    "Ignoring invalid HTTP proxy: {}",
                    self.conf.http_proxy
                ));
            }
        }
    }

    fn poll_for_token(
        &self,
        form_data: &[(&str, &str)],
        interval: std::time::Duration,
        timeout: u64,
    ) -> Result<serde_json::Value, PamError> {
        let token_url = format!("https://{}/oauth2/v1/token", self.conf.host);
        let now = std::time::Instant::now();

        while now.elapsed().as_secs() <= timeout {
            std::thread::sleep(interval);

            let resp_json: serde_json::Value =
                match self.agent.post(&token_url).send_form(form_data.to_owned()) {
                    Ok(mut resp) if resp.status().is_success() => {
                        if let Ok(res) = resp.body_mut().read_json() {
                            return Ok(res);
                        }
                        return Err(PamError::AUTH_ERR);
                    }
                    Ok(mut resp) => {
                        self.log_debug(&format!("HTTP {}", resp.status()));
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

            if resp_json["error"].as_str().unwrap_or_default() == "invalid_grant" {
                self.send_error(&format!(
                    "Polling failed: {}",
                    resp_json["error_description"].as_str().unwrap_or_default()
                ));
                return Err(PamError::AUTH_ERR);
            }
        }

        Err(PamError::AUTH_ERR)
    }

    fn factor_otp(&self, username: &str, otp: &str) -> PamError {
        self.log_info(&format!("Attempting OTP authentication for {username}"));

        let url = format!("https://{}/oauth2/v1/token", self.conf.host);
        let mut form_data = vec![
            ("client_id", self.conf.client_id.as_str()),
            ("client_secret", self.conf.client_secret.as_str()),
            ("scope", "openid"),
            ("otp", otp),
        ];

        if let Some(tok) = &self.mfa_token {
            form_data.push(("grant_type", "http://auth0.com/oauth/grant-type/mfa-otp"));
            form_data.push(("mfa_token", tok.as_str()));
        } else {
            form_data.push(("grant_type", "urn:okta:params:oauth:grant-type:otp"));
            form_data.push(("login_hint", username));
        }

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

    fn factor_password(&mut self, username: &str, password: &str) -> Option<PamError> {
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
        let resp_json: serde_json::Value = match self.agent.post(&url).send_form(form_data) {
            Ok(resp) if resp.status().is_success() => {
                self.send_info("Password authentication succeeded");
                return Some(PamError::SUCCESS);
            }
            Ok(mut resp) => {
                self.log_error(&format!("HTTP {}", resp.status()));
                match resp.body_mut().read_json() {
                    Ok(res) => res,
                    Err(_) => {
                        self.send_error("Password authentication failed");
                        return Some(PamError::AUTHINFO_UNAVAIL);
                    }
                }
            }
            Err(e) => {
                self.log_error(&e.to_string());
                self.send_error("Password authentication failed");
                return Some(PamError::AUTHINFO_UNAVAIL);
            }
        };

        let err = resp_json["error"].as_str().unwrap_or_default();
        if err == "mfa_required" {
            self.mfa_token = Some(String::from(
                resp_json["mfa_token"].as_str().unwrap_or_default(),
            ));
            self.send_info(resp_json["error_description"].as_str().unwrap_or_default());
            return None;
        }
        self.log_info(&format!("Password authentication failed: {err}"));

        Some(PamError::AUTH_ERR)
    }

    fn factor_push(&self, username: &str) -> PamError {
        self.log_info(&format!("Attempting push authentication for {username}"));

        let mut push_url = format!("https://{}/oauth2/v1/", self.conf.host);
        let mut form_data = vec![
            ("client_id", self.conf.client_id.as_str()),
            ("client_secret", self.conf.client_secret.as_str()),
            ("channel_hint", "push"),
        ];

        if let Some(tok) = &self.mfa_token {
            push_url.push_str("challenge");
            form_data.push((
                "challenge_types_supported",
                "http://auth0.com/oauth/grant-type/mfa-oob",
            ));
            form_data.push(("mfa_token", tok.as_str()));
        } else {
            push_url.push_str("oob-authenticate");
            form_data.push(("login_hint", username));
        }

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

        let mut form_data = vec![
            ("client_id", self.conf.client_id.as_str()),
            ("client_secret", self.conf.client_secret.as_str()),
            ("scope", "openid"),
            (
                "oob_code",
                resp_json["oob_code"].as_str().unwrap_or_default(),
            ),
        ];

        if let Some(tok) = &self.mfa_token {
            form_data.push(("grant_type", "http://auth0.com/oauth/grant-type/mfa-oob"));
            form_data.push(("mfa_token", tok.as_str()));
        } else {
            form_data.push(("grant_type", "urn:okta:params:oauth:grant-type:oob"));
        }

        if let Some(num_challenge) = resp_json["binding_code"].as_str() {
            // Unfortunately, OpenSSH authentication doesn't display non-prompt
            // messages as it goes.
            if self
                .pamh
                .get_service()
                .unwrap_or_default()
                .unwrap_or_default()
                .to_str()
                .unwrap_or_default()
                == "sshd"
            {
                if let Err(e) = self.pamh.conv(
                    Some(&format!(
                        "The correct answer is {num_challenge}. Press enter to continue: "
                    )),
                    PamMsgStyle::PROMPT_ECHO_OFF,
                ) {
                    self.log_error("Number challenge prompt failed to display");
                    return e;
                }
            } else if let Err(e) = self.pamh.conv(
                Some(&format!("The correct answer is {num_challenge}.")),
                PamMsgStyle::TEXT_INFO,
            ) {
                self.log_error("Number challenge prompt failed to display");
                return e;
            }
        }

        let timeout = resp_json["expires_in"].as_u64().unwrap_or(0);
        let interval = std::time::Duration::from_secs(resp_json["interval"].as_u64().unwrap_or(10));

        match self.poll_for_token(&form_data, interval, timeout) {
            Ok(_) => {
                self.send_info("Push acknowledged");
                PamError::SUCCESS
            }
            Err(e) => e,
        }
    }
}

impl PamServiceModule for PamOkta {
    fn authenticate(pamh: Pam, _: PamFlags, args: Vec<String>) -> PamError {
        let username = match pamh.get_user(None) {
            Ok(Some(user)) => user.to_str().unwrap_or_default(),
            Ok(None) => return PamError::USER_UNKNOWN,
            Err(e) => return e,
        };

        let mut oh = OktaHandle {
            pamh: &pamh,
            conf: OktaConfig {
                host: String::new(),
                client_id: String::new(),
                client_secret: String::new(),
                bypass_groups: toml::value::Array::new(),
                http_proxy: String::new(),
                debug: false,
            },
            agent: ureq_config_base().build().into(),
            mfa_token: None,
        };

        oh.log_info(&format!("Authentication attempt for {username}"));

        let mut conf_path = String::from("/etc/security/pam_okta_auth.toml");
        let mut autopush = false;
        let mut password_auth = false;
        let mut try_first_pass = false;
        let mut use_first_pass = false;

        for arg in args {
            match arg.split_once('=') {
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

        if let Ok(conf) = toml::from_str(&conf_file) {
            oh.conf = conf;
        } else {
            oh.log_error("unexpected error parsing config file");
            return PamError::SERVICE_ERR;
        }
        oh.configure_agent();

        if password_auth {
            if try_first_pass || use_first_pass {
                let password = match pamh.get_cached_authtok() {
                    Ok(Some(pass)) => pass.to_str().unwrap_or_default(),
                    Ok(_) => "",
                    Err(e) => return e,
                };
                if let Some(res) = oh.factor_password(username, password) {
                    if use_first_pass || res == PamError::SUCCESS {
                        return res;
                    }
                } else {
                    password_auth = false;
                }
            }
            if password_auth {
                let password =
                    match pamh.conv(Some("Okta password: "), PamMsgStyle::PROMPT_ECHO_OFF) {
                        Ok(Some(pass)) => pass.to_str().unwrap_or_default(),
                        Ok(_) => "",
                        Err(e) => return e,
                    };
                if let Some(res) = oh.factor_password(username, password) {
                    return res;
                }
            }
        }

        if oh.mfa_token.is_none() {
            if let Some(res) = oh.check_bypass_groups(username) {
                return res;
            }
        }

        if autopush {
            return oh.factor_push(username);
        }

        match pamh.conv(
            Some("Okta passcode (leave blank to initiate a push): "),
            PamMsgStyle::PROMPT_ECHO_ON,
        ) {
            Ok(Some(otp)) if !otp.to_str().unwrap_or_default().is_empty() => {
                oh.factor_otp(username, otp.to_str().unwrap_or_default())
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

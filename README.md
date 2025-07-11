<!--
SPDX-License-Identifier: MIT
SPDX-FileCopyrightText: © 2025 Regents of The University of Michigan

This file is part of pam_okta_auth and is distributed under the terms of
the MIT license.
-->
# pam\_okta\_auth

[![build status](https://github.com/flowerysong/pam_okta_auth/actions/workflows/build.yml/badge.svg)](https://github.com/flowerysong/pam_okta_auth/actions/workflows/build.yml) [![dependencies status](https://github.com/flowerysong/pam_okta_auth/actions/workflows/dependencies.yml/badge.svg)](https://github.com/flowerysong/pam_okta_auth/actions/workflows/dependencies.yml)

Okta authentication for Unix systems.

![animated demo](doc/pam_okta_auth.gif)

pam\_okta\_auth is a Pluggable Authentication Modules (PAM)
module designed to provide secondary authentication similar to
[duo\_unix](https://github.com/duosecurity/duo_unix) using Okta.
It also has experimental support for password-based primary
authentication.

## Deployment

The configuration file, normally located at
`/etc/security/pam_okta_auth.toml`, uses the [TOML](https://toml.io/)
format. This file contains secrets, so it must not be world readable.

Supported configuration file options and PAM options are documented
in the [man page](doc/pam_okta_auth.8.md).

Okta client credentials are required; these should be for a native
application with at least the `OTP` and `OOB` direct auth grants.

![Okta application settings](doc/okta_app_grants.png)

The application must also be assigned an authentication policy that
permits authentication with a single factor.

![Okta authentication policy](doc/okta_policy.png)

### Example Config File

```toml
host = "example.oktapreview.com"
client_id = "0deadgoffdeADGOffick"
client_secret = "6zFfFfffzfZFz6zFZFzzFZFZFfZf6Fz6F6ZfZ6f-FFFzZZ6FZ_zZFzFZ6fFzfFFz"
```

### Example PAM config

```
auth        required        pam_okta_auth.so
```

## Deployment As Primary Authentication

The password authentication flow requires client credentials for an
app with at least the `Resource Owner Password` grant; depending on
the authentication policy assigned to the app it may also need the
`MFA OTP` and `MFA OOB` grants.

This flow currently assumes that OTP (passcode) and push
authentication are always acceptable second factors when MFA is
required. It's still possible to apply a policy where only one of them
is allowed, but the end user experience is not ideal.

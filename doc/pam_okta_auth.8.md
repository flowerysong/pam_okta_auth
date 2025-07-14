PAM\_OKTA\_AUTH(8) - System Manager's Manual

# NAME

**pam\_okta\_auth** - PAM module for Okta

# SYNOPSIS

**pam\_okta\_auth.so**
\[**config\_file=**&zwnj;*FILENAME*]
\[**autopush**]
\[**password\_auth**]
\[**try\_first\_pass**]
\[**use\_first\_pass**]

# DESCRIPTION

**pam\_okta\_auth**
authenticates users against the Okta authentication service.

# OPTIONS

**config\_file=**&zwnj;*FILENAME*

> Specify a config file to load instead of
> */etc/security/pam\_okta\_auth.toml*

**autopush**

> Automatically initiate push verification instead of prompting for a passcode.

**password\_auth**

> Perform primary authentication against Okta using a password.
> The user may still be prompted to use an additional factor if the Okta
> authentication policy requires one.

**try\_first\_pass**

> Try the password (if any) supplied to a prior module in the stack before
> prompting for one.

**use\_first\_pass**

> Use the password supplied to a prior module in the stack instead of prompting
> for one.
> Primary authentication will fail if none is available.

# CONFIGURATION OPTIONS

**host**

> Okta tenant hostname (required)

**client\_id**

> OAuth2 client ID (required)

**client\_secret**

> OAuth2 client secret (required)

**debug**

> Boolean flag to enable increased log verbosity.

**http\_proxy**

> URI of the proxy to use for requests.

# SEE ALSO

PAM(8)

pam.conf(5)

pam\_okta\_auth 0.3.4-alpha.1 - 2025-07-12

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

> Perform primary authentication against Okta before prompting for a
> secondary factor.

**try\_first\_pass**

> Before prompting the user for a password, attempt authentication using one
> supplied to a prior module in the stack if possible.

**use\_first\_pass**

> Use the password supplied to a prior module instead of prompting.
> If none is available, authentication will fail.

# CONFIGURATION OPTIONS

**host**

> Okta tenant hostname (required)

**client\_id**

> OAuth2 client ID (required)

**client\_secret**

> OAuth2 client secret (required)

**bypass\_groups**

> List of groups whose members are not required to provide a secondary factor.
> This setting does not affect primary authentication if that is enabled.

**http\_proxy**

> URI of the proxy to use for requests.

# SEE ALSO

PAM(8)

pam.conf(5)

pam\_okta\_auth 0.2.1-alpha.1 - 2025-06-27

# Password Generator

A self-contained Flask web application for generating cryptographically secure random passwords and reproducible, deterministic passwords derived from credential context.

The application provides two password-generation modes:

* **Function 1 — General Password Generator:** creates new cryptographically random passwords with configurable character requirements.
* **Function 2 — Credentials-Based Password Generator:** deterministically derives a password from a Pass Key, service, account identity, version, and requested password length.

The project also includes local user accounts, encrypted Pass Key storage, optional Service History, generation quotas, session-based password history, and an administration interface.

---

## Features

### Function 1 — General Password Generator

Generate cryptographically random passwords with control over:

* Total password length
* Minimum uppercase characters
* Minimum lowercase characters
* Minimum numbers
* Minimum special characters
* Optional exclusion of visually ambiguous characters

Password generation uses Python's `secrets` module and a CSPRNG-backed shuffle.

Unallocated password positions are randomly populated from the complete available character pool.

---

### Function 2 — Credentials-Based Password Generator

Function 2 generates deterministic passwords using:

* **Pass Key**
* **Service**
* **Email address and/or username**
* **Version**
* **Password length**
* **Application instance secret**

Given the same complete set of inputs and the same application secret, the same password can be reproduced.

This allows credentials to be regenerated without storing the generated password itself.

Changing the **Version** produces a different deterministic password while preserving the other credential context.

Function 2:

* Uses PBKDF2-HMAC-SHA256
* Uses an application-instance secret in addition to the user's Pass Key
* Produces an effectively unbounded deterministic HMAC stream
* Uses rejection sampling when selecting characters
* Guarantees uppercase, lowercase, numeric, and special characters
* Excludes visually ambiguous characters
* Deterministically shuffles the resulting password

> [!IMPORTANT]
> Function 2 is only reproducible while the required inputs and application secret remain unchanged. Back up the application secret securely.

---

## Service History

Signed-in users can optionally enable **Service History**.

After a successful Function 2 generation, the normalized Service value can be recorded and later suggested when entering a service.

Service History stores only the Service identifier.

It does **not** store:

* Generated passwords
* Pass Keys
* Email addresses
* Usernames

Users can:

* Enable or disable Service History
* Browse previously used services
* Open Function 2 with a saved service
* Delete individual entries
* Clear the complete Service History

Disabling Service History prevents new entries from being recorded but does not automatically delete existing entries.

---

## Security Design

### Cryptographically secure random generation

Function 1 uses Python's `secrets` module for password character selection and `SystemRandom` for shuffling.

### Deterministic derivation

Function 2 derives its deterministic stream using PBKDF2-HMAC-SHA256 and HMAC-SHA256.

The derivation incorporates:

```text
Application Secret
        +
Pass Key
        +
Service
        +
Email
        +
Username
        +
Version
```

Password length controls the generated output length.

### Encrypted Pass Key storage

Signed-in users can optionally save their Function 2 Pass Key.

Saved Pass Keys are encrypted using **AES-256-GCM authenticated encryption** with a key derived from the user's account password using PBKDF2-HMAC-SHA256.

The application also contains migration support for its older sealed Pass Key format.

### Password storage

Account passwords are not stored directly.

They are salted and hashed using:

```text
PBKDF2-HMAC-SHA256
600,000 iterations
32-byte derived key
16-byte random salt
```

Password comparisons use constant-time comparison via `hmac.compare_digest()`.

### Session password history

Generated password history is maintained in server memory for the active browser session.

Random and deterministic password histories are kept separately.

Clearing history removes both histories and replaces the associated server-side session state.

### CSRF protection

State-changing application requests require a per-session CSRF token.

### Login protection

Login attempts are protected using both:

* Browser session identifier
* Source IP address

Password submissions are limited to one attempt per second for both identifiers.

After the configured number of failed attempts, login is temporarily locked.

### Security headers

Responses include security headers such as:

```text
Cache-Control: no-store
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
Referrer-Policy: no-referrer
Permissions-Policy
Content-Security-Policy
```

---

## Requirements

* Python 3.10+ recommended
* Flask
* cryptography

Install the required packages:

```bash
python -m pip install flask cryptography
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
cd YOUR_REPOSITORY
```

Create a virtual environment:

```bash
python -m venv .venv
```

Activate it.

### Linux / macOS

```bash
source .venv/bin/activate
```

### Windows PowerShell

```powershell
.venv\Scripts\Activate.ps1
```

Install dependencies:

```bash
python -m pip install flask cryptography
```

---

## Configuration

Before deploying the application, review the configuration section at the top of the Python file.

### Application secret

The most important configuration value is the Function 2 application-instance secret.

The application supports:

```bash
PASSGEN_APP_SECRET
```

Set it to a long, cryptographically random value.

For example, on Linux/macOS:

```bash
export PASSGEN_APP_SECRET="replace-with-a-long-random-secret"
```

PowerShell:

```powershell
$env:PASSGEN_APP_SECRET="replace-with-a-long-random-secret"
```

> [!CAUTION]
> Do not deploy the application using the built-in `CHANGE-ME...` placeholder.

The application secret directly affects every Function 2 password generated by accounts using the default secret.

**Changing or losing this secret changes the deterministic outputs.**

Store it securely and maintain an appropriate backup.

---

## Default Administrator Account

On a new database, the application creates an administrator account using the configured defaults:

```text
Username: admin
Password: changeme
```

The account is marked as requiring a password change.

> [!WARNING]
> Change the default administrator password immediately.

For a public repository, consider changing the bootstrap mechanism so production credentials are supplied through environment variables or another secure provisioning mechanism.

---

## Running the Application

Run:

```bash
python passgen19_optional_service_history.py
```

By default, the application listens on:

```text
0.0.0.0:5066
```

Open:

```text
http://localhost:5066
```

The Flask development server runs with:

```text
threaded=True
debug=False
use_reloader=False
```

The reloader is deliberately disabled because sensitive session material is maintained in process memory.

---

## HTTPS Deployment

The default configuration does not enable Secure cookies.

For deployment beyond a trusted local environment, serve the application behind HTTPS and set:

```bash
PASSGEN_SECURE_COOKIES=1
```

For example:

```bash
export PASSGEN_SECURE_COOKIES=1
```

A production deployment should normally place the Flask application behind an HTTPS-capable reverse proxy or production WSGI server rather than expose Flask's built-in server directly.

---

## Environment Variables

| Variable                      | Purpose                                    | Default              |
| ----------------------------- | ------------------------------------------ | -------------------- |
| `PASSGEN_APP_SECRET`          | Function 2 application-instance secret     | Insecure placeholder |
| `PASSGEN_SESSION_TTL_SECONDS` | Account session lifetime                   | 8 hours              |
| `PASSGEN_SECURE_COOKIES`      | Enables Secure cookie flag when set to `1` | `0`                  |

---

## Local Database

The application uses SQLite for persistent local configuration and account information.

The database is created beside the Python application as:

```text
passgen_users.sqlite3
```

It contains data including:

* User accounts
* Password hashes
* Encrypted saved Pass Keys
* User/admin settings
* Function 2 secret configuration
* Generation quota configuration and usage
* Optional Service History

Generated passwords themselves are not stored in the SQLite database by the application.

### Recommended `.gitignore`

Do not commit the local database or Python runtime files:

```gitignore
# Local application database
passgen_users.sqlite3
passgen_users.sqlite3-shm
passgen_users.sqlite3-wal

# Python
__pycache__/
*.py[cod]
*.pyo

# Virtual environments
.venv/
venv/

# Environment/configuration secrets
.env
.env.*
```

---

## User Accounts

The application supports registered accounts and guest access.

Registered users can access account functionality including:

* Changing their password
* Saving an encrypted Pass Key
* Revealing a saved Pass Key after password verification
* Removing their saved Pass Key
* Enabling/disabling Service History
* Logging out other account sessions

A password change re-encrypts the saved Pass Key using a key derived from the new password.

---

## Administration

Administrators can manage:

* User creation
* Usernames and display names
* Administrator privileges
* Password resets
* Default Function 2 secret
* User-specific Function 2 secret overrides
* Session timeout
* Guest generation quotas
* Per-user generation quotas
* Quota usage

Password resets clear the affected user's encrypted saved Pass Key because the old password-derived encryption key is no longer available.

---

## Generation Quotas

Generation quotas can be configured independently for guests and registered users.

Supported periods include:

* Per minute
* Per hour
* Per day
* Per rolling 7 days
* Per rolling 30 days

Quotas can independently apply to:

```text
Function 1
Function 2
```

A global hard-coded safety rate limit also applies regardless of whether account-level quotas are enabled.

---

## Using Function 1

1. Select **Function 1: General Generator**.
2. Choose the total password length.
3. Configure the desired minimum character counts.
4. Choose whether ambiguous characters should be excluded.
5. Click **Generate**.
6. Copy the generated password.

Generating again produces a new random password.

---

## Using Function 2

1. Select **Function 2: Credentials Generator**.
2. Enter your Pass Key.
3. Enter the Service.
4. Enter an email address, username, or both.
5. Enter the Version.
6. Select the required password length.
7. Click **Generate**.

To reproduce the password later, provide the same inputs and use an application configuration with the same Function 2 secret.

### Example

```text
Pass Key:       your-private-pass-key
Service:        example-service
Email:          user@example.com
Username:       exampleuser
Version:        0
Password Length: 32
```

Increment the Version when a credential needs to be rotated:

```text
Version 0 -> Password A
Version 1 -> Password B
Version 2 -> Password C
```

Returning to Version `0` with otherwise identical inputs reproduces Password A.

---

## Input Normalization

Function 2 normalizes some credential context before derivation.

### Service

Service names:

* Are required
* Accept ASCII letters, numbers, spaces, and hyphens
* Are converted to lowercase
* Preserve spaces and hyphens

For example:

```text
GitHub
github
GITHUB
```

normalize to the same Service value.

However:

```text
example service
example-service
```

remain different values and therefore produce different deterministic outputs.

### Email and Username

Email addresses and usernames are normalized to lowercase before validation.

At least one of **Email** or **Username** must be supplied.

---

## Keyboard Shortcuts

The web interface provides keyboard shortcuts when focus is not inside an input field.

| Key | Action                          |
| --- | ------------------------------- |
| `1` | Function 1                      |
| `2` | Function 2                      |
| `C` | Clear session history           |
| `M` | Mask/unmask session history     |
| `S` | Service History                 |
| `P` | Account                         |
| `A` | Administration, when authorized |
| `H` | Help                            |

---

## Health Check

A simple health endpoint is available:

```http
GET /health
```

Successful response:

```json
{
  "ok": true
}
```

This can be used by reverse proxies, containers, or monitoring systems for basic application availability checks.

---

## Project Architecture

The application is intentionally self-contained.

```text
passgen19_optional_service_history.py
│
├── Configuration
├── SQLite persistence
│   ├── users
│   ├── settings
│   ├── quota_usage
│   └── service_history
│
├── Authentication
├── Login protection
├── In-memory sessions
├── CSRF protection
├── Password generation
│   ├── Function 1 — random
│   └── Function 2 — deterministic
├── Generation quotas
├── Embedded HTML/CSS/JavaScript
├── Account interface
├── Service History
├── Administration
├── JSON API endpoints
└── Flask entry point
```

Templates, CSS, and JavaScript are embedded directly in the Python source, so separate template and static directories are not required.

---

## API Endpoints

The application exposes endpoints including:

```text
GET   /
GET   /login
POST  /login
GET   /guest
GET   /logout

GET   /account
POST  /account

GET   /service-history
POST  /service-history

GET   /admin
POST  /admin

GET   /help
GET   /health

GET   /api/history
POST  /api/history/clear

POST  /api/generate/random
POST  /api/generate/derived
```

Generation and other state-changing requests are protected with CSRF validation.

---

## Threat Model and Limitations

This project implements several defensive controls, but it should not be interpreted as independently security-audited software.

Important considerations include:

* Anyone who obtains the Function 2 Pass Key and the necessary derivation context may be able to reproduce credentials if they also have access to the required application secret.
* Losing or changing the Function 2 application secret prevents reproduction of existing deterministic outputs that depended on it.
* A saved Pass Key is protected by encryption derived from the user's account password; account-password security therefore matters.
* The SQLite database contains security-sensitive account and configuration information and must be protected appropriately.
* TLS/HTTPS is required when transmitting credentials across untrusted networks.
* Flask's built-in development server is not intended to be the production-facing web server.
* Application source, configuration, dependencies, deployment architecture, and cryptographic design should undergo an appropriate security review before production use.

---

## Security Recommendations

Before exposing the application outside a development environment:

1. Replace the default Function 2 application secret.
2. Change the default administrator password.
3. Enable HTTPS.
4. Set `PASSGEN_SECURE_COOKIES=1`.
5. Restrict filesystem permissions on the SQLite database.
6. Keep secrets outside source control.
7. Add the SQLite database and environment files to `.gitignore`.
8. Use a supported production WSGI deployment architecture.
9. Keep Python, Flask, `cryptography`, and the operating system patched.
10. Perform an independent security review before relying on the application for sensitive production credentials.

---

## Dependencies

Primary third-party dependencies:

* [Flask](https://flask.palletsprojects.com/) — web application framework
* [cryptography](https://cryptography.io/) — AES-GCM authenticated encryption

The remaining functionality primarily uses Python's standard library.

---

## Development

Because the application embeds its templates, CSS, JavaScript, API, persistence layer, and password-generation logic into a single Python file, it can be run without a separate frontend build process.

For development:

```bash
python passgen19_optional_service_history.py
```

The `/health` endpoint can be used to confirm that the server is responding.

---

## Disclaimer

This software handles security-sensitive material.

Review the implementation, deployment configuration, threat model, and cryptographic assumptions before using it to protect important credentials.

No password-generation system should be treated as secure solely because it uses established cryptographic primitives; the complete implementation and deployment environment must also be evaluated.

---

## License



Before publishing the repository, add a `LICENSE` file and update this section with the license you intend to use.

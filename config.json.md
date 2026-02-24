# config.json Reference

Place `config.json` in the root of the Usgromana plugin directory.

## Default config (HS256 mode)

```json
{
    "log": "usgromana.log",
    "log_levels": ["INFO"],
    "jwt_token_algorithm": "HS256",
    "secret_key_env": "SECRET_KEY",
    "access_token_expiration_hours": 12,
    "max_access_token_expiration_hours": 8760,
    "blacklist_after_attempts": 5,
    "free_memory_on_logout": true,
    "force_https": false,
    "seperate_users": true,
    "manager_admin_only": true,
    "enable_guest_account": true
}
```

## Available Options

### Logging

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `log` | string | `"usgromana.log"` | Path to the log file, relative to the plugin directory. |
| `log_levels` | array of strings | `["INFO"]` | Log levels to emit. Valid values: `"DEBUG"`, `"INFO"`, `"WARNING"`, `"ERROR"`. |

---

### JWT Authentication

#### `jwt_token_algorithm`

- **Type:** string
- **Default:** `"HS256"`
- **Values:** `"HS256"` or `"RS256"`

Selects the JWT signing algorithm. Use `HS256` for shared-secret signing (typical self-hosted setup) or `RS256` for asymmetric key signing (supports externally-issued JWTs, e.g. from an SSO/identity provider).

---

#### HS256 options (used when `jwt_token_algorithm` is `"HS256"`)

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `secret_key_env` | string | `"SECRET_KEY"` | Name of the environment variable containing the HS256 secret key. Used when `secret_key_b64` is not set. |
| `secret_key_b64` | string | _(none)_ | Base64url-encoded HS256 secret key, embedded directly in config. Takes priority over `secret_key_env`. If neither is set, a random key is generated on each startup (all sessions are invalidated on restart). |

**Example:**
```json
{
    "jwt_token_algorithm": "HS256",
    "secret_key_env": "MY_SECRET_KEY"
}
```

---

#### RS256 options (used when `jwt_token_algorithm` is `"RS256"`)

| Option | Type | Required | Description |
|--------|------|----------|-------------|
| `jwt_rs256_public_key` | string | **Yes** | Base64url-encoded RSA public key (PEM). Used to verify JWT signatures. **Required** — startup will fail without this. |
| `jwt_rs256_private_key` | string | No | Base64url-encoded RSA private key (PEM). Required only if Usgromana is issuing its own JWTs. Omit when tokens are issued by an external identity provider. |

**Example (external JWT provider — verify only):**
```json
{
    "jwt_token_algorithm": "RS256",
    "jwt_rs256_public_key": "<base64url-encoded public key>"
}
```

**Example (self-issued RS256 JWTs):**
```json
{
    "jwt_token_algorithm": "RS256",
    "jwt_rs256_public_key": "<base64url-encoded public key>",
    "jwt_rs256_private_key": "<base64url-encoded private key>"
}
```

---

### Token Expiration

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `access_token_expiration_hours` | integer | `12` | Default lifetime of an access token, in hours. |
| `max_access_token_expiration_hours` | integer | `8760` | Maximum allowed token lifetime a client may request, in hours. `8760` = 1 year. |

---

### Network & Security

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `blacklist_after_attempts` | integer | `5` | Number of failed login attempts before an IP is added to the blacklist. Set to `0` to disable automatic blacklisting. |
| `force_https` | boolean | `false` | When `true`, reject requests that do not arrive over HTTPS (checks `X-Forwarded-Proto: https`). Useful when behind a reverse proxy. |

---

### User & Access Control

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `seperate_users` | boolean | `true` | When `true`, each user's data/outputs are isolated from other users. *(Note: intentional spelling in config key.)* |
| `manager_admin_only` | boolean | `true` | When `true`, only admin users can access the user manager interface. |
| `enable_guest_account` | boolean | `true` | When `true`, a guest account is available for unauthenticated access. When `false`, guest account creation and guest logins are blocked. Note: existing guest JWTs remain valid until they expire. |
| `free_memory_on_logout` | boolean | `true` | When `true`, GPU/system memory is freed when a user logs out. |

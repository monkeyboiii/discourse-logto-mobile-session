# discourse-logto-mobile-session

> AI Assistant Guide for Discourse Logto Mobile Session Plugin

## Overview

A Discourse plugin that enables native mobile apps to exchange Logto OIDC access tokens for Discourse session cookies, allowing seamless authentication transitions from native app context to WebView.

**Version:** 0.1.2
**Author:** monkeyboiii
**Discourse Version Required:** 2.7.0+

### Core Flow

```
Mobile App (Logto SDK) → Access Token
         ↓
POST /api/auth/mobile-session
         ↓
Token Validation (userinfo OR JWT)
         ↓
User Provisioning (find/create)
         ↓
Session Creation (log_on_user)
         ↓
Cookie Response (_t + _forum_session) → WebView
```

---

## Architecture

### Components

1. **OidcMetadata** (`lib/logto_mobile/oidc_metadata.rb`) - ⭐ NEW KEY COMPONENT
   - Centralized OIDC discovery document and JWKS fetching
   - Redis-backed caching (10min for discovery, 1hr for JWKS)
   - Automatic cache invalidation on setting changes
   - Provides issuer, userinfo_endpoint, jwks_uri, algorithms

2. **TokenValidator** (`lib/logto_mobile/token_validator.rb`)
   - Validates tokens via userinfo endpoint OR JWT signature
   - Uses OidcMetadata for all endpoints and keys
   - Supports feature-flag switching between methods

3. **UserProvisioner** (`lib/logto_mobile/user_provisioner.rb`)
   - Finds users by email or logto_sub custom field
   - Creates new users with auto-activation
   - Stores Logto metadata in custom fields
   - Creates UserAssociatedAccount for OIDC linking

4. **SessionManager** (`lib/logto_mobile/session_manager.rb`)
   - Creates Discourse sessions via `log_on_user`
   - Returns BOTH cookies: `_t` (auth token) and `_forum_session`
   - Uses Discourse native session settings (no custom TTL)
   - Cookie domain from `force_hostname` or request host

5. **SessionController** (`app/controllers/logto_mobile/session_controller.rb`)
   - API endpoints: POST/DELETE /api/auth/mobile-session, GET /health
   - Rate limiting, client type validation, error handling

### File Structure

```
discourse-logto-mobile-session/
├── plugin.rb                                      # Plugin manifest, routes, cache hooks
├── config/
│   ├── settings.yml                               # Site settings (no cookie_ttl setting!)
│   └── locales/
│       ├── server.en.yml                          # English translations
│       └── server.zh_CN.yml                       # Chinese translations
├── lib/logto_mobile/
│   ├── oidc_metadata.rb                           # ⭐ OIDC discovery/JWKS caching service
│   ├── token_validator.rb                        # Token validation (userinfo/JWT)
│   ├── user_provisioner.rb                       # User creation/matching
│   └── session_manager.rb                        # Session/cookie handling
├── app/controllers/logto_mobile/
│   └── session_controller.rb                     # API controller
└── spec/
    ├── fixtures/
    │   ├── openid-configuration.json              # Mock discovery document
    │   └── jwks.json                              # Mock JWKS
    ├── lib/logto_mobile/
    │   ├── oidc_metadata_spec.rb
    │   ├── token_validator_spec.rb
    │   ├── user_provisioner_spec.rb
    │   └── session_manager_spec.rb
    └── requests/
        └── logto_mobile_session_spec.rb           # Integration tests
```

---

## Key Implementation Details

### 1. OIDC Metadata Service (OidcMetadata)

**CRITICAL:** This module was added in recent commits and is NOT in older documentation.

- Fetches discovery document from `SiteSetting.openid_connect_discovery_document`
- Caches in Discourse.cache with TTLs (discovery: 10min, JWKS: 1hr)
- Used by TokenValidator to get endpoints and keys
- Auto-refreshes on `site_setting_changed` events
- Validates required fields: issuer, jwks_uri, userinfo_endpoint

**Cache Keys:**
- `logto_mobile:oidc_discovery`
- `logto_mobile:jwks`

**Event Hook in plugin.rb:**
```ruby
on(:site_setting_changed) do |setting_name, old_value, new_value|
  case setting_name
  when :logto_mobile_session_enabled, :openid_connect_discovery_document,
       :logto_mobile_session_validation_method
    LogtoMobile::OidcMetadata.refresh_all!
  end
end
```

### 2. Token Validation Methods

**Userinfo Method** (default):
- Calls Logto's userinfo endpoint with Bearer token
- Returns user claims directly
- Simpler but requires external HTTP call

**JWT Method**:
- Validates signature using JWKS from OidcMetadata
- Supports multiple algorithms (derived from JWKS or discovery doc)
- Faster, no external call after JWKS cached
- Falls back to RS256 if no algorithm specified

**Algorithm Detection:**
1. First tries to extract from JWKS keys (`alg` field)
2. Falls back to discovery doc's `id_token_signing_alg_values_supported`
3. Defaults to `["RS256"]`

### 3. Session Cookie Handling

**IMPORTANT CHANGE:** Returns TWO cookies, not one!

```ruby
{
  auth_token: {
    name: "_t",
    value: "...",  # Primary authentication token
    domain: "forum.example.com",
    path: "/",
    expires_at: "2024-12-01T12:00:00Z",  # nil if non-persistent
    secure: true,
    http_only: true,
    same_site: "Lax"
  },
  session_cookie: {
    name: "_forum_session",
    value: "...",  # Rails session cookie
    # ... same structure
  }
}
```

**Session Expiration:**
- Uses Discourse's native `persistent_sessions` setting
- If enabled: `maximum_session_age` hours from now
- If disabled: nil (session cookie, expires when browser closes)

**Cookie Domain Logic:**
1. Check `SiteSetting.force_hostname`
2. Check `GlobalSetting.force_hostname` (if available)
3. Fall back to request host
4. Returns FULL domain (e.g., `forum.example.com`), not apex (`.example.com`)

### 4. Site Settings

**Available Settings** (in config/settings.yml):

```yaml
logto_mobile_session_enabled: false                    # Master enable switch
logto_mobile_session_validation_method: "userinfo"     # "userinfo" or "jwt"
logto_mobile_session_auto_approve_users: true          # Auto-approve new users
logto_mobile_session_require_verified_email: true      # Enforce email_verified claim
logto_mobile_session_allowed_client_types: "ios_native,android_native"
logto_mobile_session_rate_limit_per_minute: 10
```

**REMOVED from original docs:**
- `logto_mobile_session_cookie_ttl` - Uses Discourse native session settings instead

**Required External Settings:**
- `openid_connect_enabled: true`
- `openid_connect_discovery_document: "https://tenant.logto.app/oidc/.well-known/openid-configuration"`

### 5. User Provisioning Logic

**Matching Strategy:**
1. First, search by email: `User.find_by_email(email)`
2. If not found, search by custom field: `UserCustomField.where(name: 'logto_sub', value: sub)`

**User Creation:**
- Username: sanitized from Logto username → email-derived → random
- Password: `SecureRandom.hex(32)` (user won't use it)
- Active: `true` (Logto pre-verified)
- Approved: based on `auto_approve_users` setting
- Trust level: 0
- Custom fields: `logto_sub`, `logto_email_verified`, `logto_last_auth`

**Associated Account:**
```ruby
UserAssociatedAccount.create!(
  provider_name: 'oidc',
  provider_uid: user_info[:sub],
  user_id: user.id,
  extra: { email, name, created_via: 'mobile_session_exchange' }.to_json
)
```

### 6. Rate Limiting

**Implementation:** Redis-based, per-IP
- Key: `mobile_session:#{request.ip}`
- Default: 10 requests/minute
- TTL: 60 seconds
- Returns 429 with `retry_after` on exceed

---

## API Reference

### POST /api/auth/mobile-session

**Request:**
```json
{
  "access_token": "eyJhbGc...",
  "client_type": "ios_native"  // Required: must be in allowed_client_types
}
```

OR with Bearer header:
```
Authorization: Bearer eyJhbGc...
```

**Success Response (201):**
```json
{
  "success": true,
  "auth_token": {
    "name": "_t",
    "value": "...",
    "domain": "forum.example.com",
    "path": "/",
    "expires_at": "2024-12-01T12:00:00Z",
    "secure": true,
    "http_only": true,
    "same_site": "Lax"
  },
  "session_cookie": {
    "name": "_forum_session",
    // ... same structure
  },
  "user": {
    "id": 123,
    "username": "johndoe",
    "email": "[email protected]",
    "name": "John Doe",
    "avatar_template": "https://..."
  },
  "validation_method": "jwt"
}
```

**Error Responses:**
- 400: Missing `client_type`
- 401: Invalid/expired token, validation error
- 403: Disallowed client type
- 429: Rate limit exceeded
- 503: Plugin or OIDC not enabled

### DELETE /api/auth/mobile-session

Destroys current session. Returns `{"success": true}`.

### GET /api/auth/mobile-session/health

**Response:**
```json
{
  "healthy": true,
  "checks": {
    "plugin_enabled": true,
    "oidc_enabled": true,
    "oidc_configured": true,
    "validation_method": "jwt",
    "rate_limiting": true
  },
  "version": "0.1.2"
}
```

---

## Development Workflow

### Running Tests

```bash
# From Discourse root
bundle exec rspec plugins/discourse-logto-mobile-session/spec
```

**Test Structure:**
- Unit tests: `spec/lib/logto_mobile/*_spec.rb`
- Integration tests: `spec/requests/logto_mobile_session_spec.rb`
- Fixtures: `spec/fixtures/*.json`

**Key Test Patterns:**
- Stub HTTP requests with WebMock
- Clear Discourse.cache before/after
- Stub discovery and JWKS endpoints BEFORE setting site settings (to handle refresh_all! hook)

### Code Style

- **Frozen string literals:** All files use `# frozen_string_literal: true`
- **Formatting:** Uses Rubocop (Discourse standards)
- **Namespacing:** All classes under `LogtoMobile` module
- **Error handling:** Custom exceptions (`ValidationError`, `ProvisioningError`)
- **Logging:** Prefix all logs with `[LogtoMobileSession]`

### Recent Changes (Git History)

- `cd5ab4c` - Cookie reimplementation + linting
- `b41a180` - Fetch from OIDC discovery_url (OidcMetadata added)
- `e09af93` - Hard-coded endpoint removal
- `e80ec5d` - Session manager & controller review
- `d1e2428` - Code review cleanup

**Major Evolution:**
1. Started with hard-coded endpoints
2. Refactored to use discovery document
3. Added centralized OidcMetadata service
4. Implemented cookie handling improvements

---

## Common Patterns for AI Assistants

### Adding New Features

1. **Update OidcMetadata** if new OIDC endpoints needed
2. **Add settings** to `config/settings.yml` + localizations
3. **Write tests first** (TDD approach used in this codebase)
4. **Update health check** in SessionController if new dependencies
5. **Handle cache invalidation** in plugin.rb's `site_setting_changed` hook

### Debugging Issues

**Token validation failures:**
- Check OidcMetadata.discovery! for discovery doc issues
- Verify JWKS fetching: `OidcMetadata.fetch_jwks(force: true)`
- Check algorithm detection: `OidcMetadata.algorithms`

**Session cookie issues:**
- Verify `force_hostname` setting
- Check `persistent_sessions` and `maximum_session_age`
- Confirm both `_t` and `_forum_session` cookies returned

**User provisioning failures:**
- Check email normalization (downcased, stripped)
- Verify custom fields saved: `logto_sub`, `logto_email_verified`
- Ensure UserAssociatedAccount created with provider_name: 'oidc'

### Code Conventions

**When modifying validators:**
- Return hash with `:success`, `:error`, `:message` keys
- Use symbolized keys in normalized user_info
- Raise `ValidationError` for validation failures

**When modifying provisioners:**
- Match by email first, then logto_sub
- Always update `logto_last_auth` custom field
- Raise `ProvisioningError` for creation failures

**When modifying controllers:**
- Use rescue_from for custom error types
- Never log access tokens (security!)
- Return proper HTTP status codes
- Include retry_after in rate limit responses

**When modifying metadata service:**
- Use Discourse.cache, not direct Redis
- Include TTL on all cached data
- Validate required fields from discovery doc
- Use Faraday with FinalDestination::FaradayAdapter (Discourse pattern)

### Testing Checklist

- [ ] Unit tests for new service methods
- [ ] Integration test for API endpoint changes
- [ ] WebMock stubs for external HTTP calls
- [ ] Cache clearing in before/after hooks
- [ ] Test both validation methods (userinfo + JWT)
- [ ] Test rate limiting scenarios
- [ ] Test error handling paths
- [ ] Update fixtures if OIDC response format changes

---

## Security Considerations

### Implemented Protections

1. **Rate Limiting:** 10 req/min per IP (configurable)
2. **Client Type Validation:** Whitelist of allowed client types
3. **Token Validation:** Via Logto (userinfo or JWT signature)
4. **Email Verification:** Enforced via `require_verified_email` setting
5. **HttpOnly Cookies:** Not accessible to JavaScript
6. **Secure Flag:** HTTPS-only in production
7. **SameSite=Lax:** CSRF protection
8. **No Token Logging:** Access tokens never written to logs
9. **CSRF Skip:** Only for API endpoints (skip_before_action :verify_authenticity_token)

### Security Notes for AI Assistants

- **NEVER log access tokens** - Use `[REDACTED]` or similar
- **Validate all user inputs** - client_type, access_token params
- **Use HTTPS in production** - Check `Rails.env.production?`
- **Trust Logto for identity** - Don't bypass email_verified checks
- **Audit custom fields** - `logto_sub` is the source of truth

### Known TODOs in Code

From `user_provisioner.rb:63-64`:
```ruby
# REVIEW: TODO: May very much wait till later when actual user complains
# about inconsistent email vs OpenID Connect email.
```

From `user_provisioner.rb:97`:
```ruby
# TODO: More custom fields here
```

---

## Mobile Client Integration

### iOS Example (Swift)

```swift
// 1. Get access token from Logto SDK
let accessToken = try await logtoClient.getAccessToken()

// 2. Exchange for Discourse session
let response = try await exchangeToken(accessToken)

// 3. Inject both cookies into WKWebView
let cookieStore = webView.configuration.websiteDataStore.httpCookieStore

// Auth token cookie (_t)
let authCookie = HTTPCookie(properties: [
    .name: response.authToken.name,
    .value: response.authToken.value,
    .domain: response.authToken.domain,
    .path: response.authToken.path,
    .secure: response.authToken.secure,
    .expires: ISO8601DateFormatter().date(from: response.authToken.expiresAt) ?? Date()
])!
await cookieStore.setCookie(authCookie)

// Session cookie (_forum_session)
let sessionCookie = HTTPCookie(properties: [
    .name: response.sessionCookie.name,
    .value: response.sessionCookie.value,
    .domain: response.sessionCookie.domain,
    .path: response.sessionCookie.path,
    .secure: response.sessionCookie.secure,
    .expires: ISO8601DateFormatter().date(from: response.sessionCookie.expiresAt) ?? Date()
])!
await cookieStore.setCookie(sessionCookie)

// 4. Load forum
webView.load(URLRequest(url: URL(string: "https://forum.example.com")!))
```

**IMPORTANT:** Inject BOTH cookies (`_t` and `_forum_session`) for full authentication.

---

## Configuration Checklist

### Discourse Admin Settings

- [ ] **Login → openid connect enabled**: ✓
- [ ] **Login → openid connect discovery document**: `https://tenant.logto.app/oidc/.well-known/openid-configuration`
- [ ] **Login → openid connect client id**: Your Logto app ID
- [ ] **Login → openid connect client secret**: Your Logto app secret
- [ ] **Plugins → logto mobile session enabled**: ✓
- [ ] **Plugins → logto mobile session validation method**: `userinfo` (start) → `jwt` (production)
- [ ] **Plugins → logto mobile session allowed client types**: `ios_native,android_native`
- [ ] **Plugins → logto mobile session rate limit per minute**: 10

### Logto Application Settings

- [ ] **Redirect URI**: `https://forum.example.com/auth/oidc/callback`
- [ ] **Allowed scopes**: `openid`, `profile`, `email`
- [ ] **Token expiration**: 1 hour (recommended)
- [ ] **Require email verification**: ✓ (if using require_verified_email)

### Environment Verification

```bash
# Health check
curl https://forum.example.com/api/auth/mobile-session/health

# Should return:
# {"healthy": true, "checks": {...}, "version": "0.1.2"}
```

---

## Troubleshooting Guide

### "OIDC discovery document not configured"

**Cause:** `openid_connect_discovery_document` not set or invalid

**Fix:**
1. Set in Admin → Settings → Login
2. Format: `https://tenant.logto.app/oidc/.well-known/openid-configuration`
3. Check OidcMetadata.refresh_all! to clear cache

### "Discovery document missing required fields"

**Cause:** Discovery doc missing `issuer`, `jwks_uri`, or `userinfo_endpoint`

**Fix:**
1. Verify discovery URL is correct
2. Test manually: `curl https://tenant.logto.app/oidc/.well-known/openid-configuration`
3. Ensure Logto instance is properly configured

### "JWT validation failed"

**Cause:** Algorithm mismatch or JWKS fetch failure

**Fix:**
1. Check algorithms: `OidcMetadata.algorithms` should return non-empty array
2. Verify JWKS accessible: `curl https://tenant.logto.app/oidc/jwks`
3. Force refresh: `OidcMetadata.fetch_jwks(force: true)`
4. Check token is from correct issuer

### "Token is invalid or expired"

**Cause:** Token expired, revoked, or from wrong tenant

**Fix:**
1. Verify token freshness (Logto default: 1hr expiration)
2. Ensure token is for the correct Logto application
3. Check token scopes include `openid`, `email`, `profile`
4. Try userinfo method to see detailed error

### "Email not verified in Logto"

**Cause:** User's email not verified, setting enforces verification

**Fix:**
1. Verify user in Logto admin console
2. OR disable: `logto_mobile_session_require_verified_email: false`

### Session cookie not working in WebView

**Cause:** Missing cookie, wrong domain, or security mismatch

**Fix:**
1. Ensure BOTH `_t` and `_forum_session` cookies injected
2. Verify cookie domain matches WebView URL
3. Check `secure` flag matches HTTPS usage
4. Confirm cookie not expired

---

## Localization

**Supported Locales:**
- English (`server.en.yml`)
- Chinese Simplified (`server.zh_CN.yml`)

**Adding New Locale:**
1. Copy `config/locales/server.en.yml`
2. Rename to `server.{locale}.yml`
3. Translate `site_settings` strings
4. Test in Discourse admin interface

---

## Performance Notes

### Caching Strategy

- **Discovery Document:** 10 minutes (frequent enough for endpoint changes)
- **JWKS:** 1 hour (keys rotate infrequently)
- **Redis Keys:** Prefixed with `logto_mobile:` for easy identification

### Optimization Tips

1. **Use JWT validation** for production (eliminates userinfo HTTP call)
2. **Monitor cache hit rates** in Redis
3. **Adjust TTLs** in OidcMetadata if needed
4. **Pre-warm cache** via `OidcMetadata.refresh_all!` on deploy

### Scaling Considerations

- Rate limiting is per-IP, may need adjustment for NAT environments
- JWKS cache shared across all app servers (Redis)
- No persistent state in plugin (stateless)

---

## Version History

- **0.1.2** - Current version (cookie improvements, linting)
- **0.1.x** - OIDC metadata service, discovery integration
- **0.0.x** - Initial implementation

## Related Documentation

- [Discourse Plugin Development](https://meta.discourse.org/t/beginners-guide-to-creating-discourse-plugins/30515)
- [Logto OIDC Documentation](https://docs.logto.io/docs/recipes/integrate-logto/)
- [OpenID Connect Specification](https://openid.net/specs/openid-connect-core-1_0.html)

---

**Last Updated:** 2024-11 (matches git commit cd5ab4c)
**Maintainer:** monkeyboiii
**Repository:** https://github.com/monkeyboiii/discourse-logto-mobile-session

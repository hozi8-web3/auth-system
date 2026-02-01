# API Reference

Complete API documentation for the Enterprise Auth Server.

---

## Base URL

```
http://localhost:3000/api/v1
```

## Authentication

Most endpoints require authentication via Bearer token:

```
Authorization: Bearer <access_token>
```

---

## Auth Endpoints

### Register
```http
POST /auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass@123!",
  "firstName": "John",
  "lastName": "Doe"
}
```

**Response:** `201 Created`
```json
{
  "success": true,
  "message": "Registration successful. Please verify your email.",
  "data": {
    "userId": "uuid",
    "email": "user@example.com"
  }
}
```

---

### Login
```http
POST /auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass@123!"
}
```

**Response:** `200 OK`
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbG...",
    "accessTokenExpiry": "2024-01-01T00:15:00Z",
    "user": {
      "id": "uuid",
      "email": "user@example.com",
      "firstName": "John",
      "lastName": "Doe",
      "emailVerified": true,
      "twoFactorEnabled": false
    }
  }
}
```

---

### Logout
```http
POST /auth/logout
Authorization: Bearer <token>
```

---

### Refresh Token
```http
POST /auth/refresh
Cookie: refreshToken=<token>
```

---

### Get Current User
```http
GET /auth/me
Authorization: Bearer <token>
```

---

### Forgot Password
```http
POST /auth/forgot-password
Content-Type: application/json

{
  "email": "user@example.com"
}
```

---

### Reset Password
```http
POST /auth/reset-password
Content-Type: application/json

{
  "token": "reset-token-from-email",
  "password": "NewSecurePass@123!"
}
```

---

## Two-Factor Authentication

### Setup 2FA
```http
POST /auth/2fa/setup
Authorization: Bearer <token>
```

Returns QR code and secret for authenticator app.

---

### Enable 2FA
```http
POST /auth/2fa/enable
Authorization: Bearer <token>
Content-Type: application/json

{
  "code": "123456"
}
```

---

### Verify 2FA (during login)
```http
POST /auth/2fa/verify
Content-Type: application/json

{
  "tempToken": "temp-token-from-login",
  "code": "123456"
}
```

---

### Disable 2FA
```http
POST /auth/2fa/disable
Authorization: Bearer <token>
Content-Type: application/json

{
  "code": "123456"
}
```

---

## OAuth

### Initiate OAuth
```http
GET /oauth/:provider
# provider: google, github, microsoft
```

Returns authorization URL to redirect user.

---

### OAuth Callback
```http
GET /oauth/:provider/callback?code=xxx&state=xxx
```

Handled automatically by OAuth flow.

---

### Link OAuth Account
```http
POST /oauth/:provider/link
Authorization: Bearer <token>
```

---

### Unlink OAuth Account
```http
DELETE /oauth/:provider/unlink
Authorization: Bearer <token>
```

---

### Get Linked Accounts
```http
GET /oauth/accounts
Authorization: Bearer <token>
```

---

## Passwordless Authentication

### Request Magic Link
```http
POST /passwordless/magic-link/request
Content-Type: application/json

{
  "email": "user@example.com"
}
```

---

### Verify Magic Link
```http
POST /passwordless/magic-link/verify
Content-Type: application/json

{
  "token": "magic-link-token"
}
```

---

### WebAuthn Registration Options
```http
POST /passwordless/webauthn/register/options
Authorization: Bearer <token>
```

---

### WebAuthn Register Verify
```http
POST /passwordless/webauthn/register/verify
Authorization: Bearer <token>
Content-Type: application/json

{
  "credential": { ... },
  "deviceName": "MacBook Pro"
}
```

---

### WebAuthn Login Options
```http
POST /passwordless/webauthn/login/options
Content-Type: application/json

{
  "email": "user@example.com"
}
```

---

### WebAuthn Login Verify
```http
POST /passwordless/webauthn/login/verify
Content-Type: application/json

{
  "credential": { ... }
}
```

---

## API Keys

### Create API Key
```http
POST /api-keys
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "My API Key",
  "scopes": ["read", "write"],
  "expiresInDays": 30
}
```

---

### List API Keys
```http
GET /api-keys
Authorization: Bearer <token>
```

---

### Get API Key
```http
GET /api-keys/:keyId
Authorization: Bearer <token>
```

---

### Update API Key
```http
PATCH /api-keys/:keyId
Authorization: Bearer <token>
Content-Type: application/json

{
  "name": "Updated Name",
  "isActive": false
}
```

---

### Revoke API Key
```http
DELETE /api-keys/:keyId
Authorization: Bearer <token>
```

---

### Rotate API Key
```http
POST /api-keys/:keyId/rotate
Authorization: Bearer <token>
```

---

## Admin Endpoints

> Requires admin role with valid signature

### Get System Stats
```http
GET /admin/stats
Authorization: Bearer <admin-token>
```

---

### List Users
```http
GET /admin/users?page=1&limit=20&search=john
Authorization: Bearer <admin-token>
```

---

### Get User Details
```http
GET /admin/users/:userId
Authorization: Bearer <admin-token>
```

---

### Update User Role
```http
PUT /admin/users/:userId/role
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "role": "MODERATOR"
}
```

---

### Lock User
```http
POST /admin/users/:userId/lock
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "durationMinutes": 60,
  "reason": "Suspicious activity"
}
```

---

### Unlock User
```http
POST /admin/users/:userId/unlock
Authorization: Bearer <admin-token>
```

---

### Force Password Reset
```http
POST /admin/users/:userId/reset-password
Authorization: Bearer <super-admin-token>
Content-Type: application/json

{
  "newPassword": "NewSecurePass@123!"
}
```

---

### Get Audit Logs
```http
GET /admin/audit-logs?userId=xxx&action=LOGIN&limit=50
Authorization: Bearer <admin-token>
```

---

## Error Responses

All errors follow this format:

```json
{
  "success": false,
  "error": "Human readable error message",
  "code": "ERROR_CODE"
}
```

### Common Error Codes

| Code | HTTP Status | Description |
|------|-------------|-------------|
| `VALIDATION_ERROR` | 400 | Invalid request data |
| `MISSING_AUTH_HEADER` | 401 | No Authorization header |
| `INVALID_TOKEN` | 401 | Token is invalid |
| `TOKEN_EXPIRED` | 401 | Token has expired |
| `ACCESS_DENIED` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `RATE_LIMIT_EXCEEDED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |

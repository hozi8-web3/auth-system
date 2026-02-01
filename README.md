# 🔐 Enterprise Authentication Server

A military-grade, production-ready authentication server built with Node.js, TypeScript, and enterprise security standards.

## ✨ Features

### Core Authentication
| Feature | Description |
|---------|-------------|
| **JWT RS256** | Asymmetric token signing with RSA-4096 keys |
| **Refresh Token Rotation** | Automatic token rotation with reuse detection |
| **Argon2id Hashing** | OWASP-recommended password hashing |
| **Two-Factor Auth** | TOTP with QR codes + backup codes |
| **Rate Limiting** | Redis-backed per-endpoint limiting |
| **Account Lockout** | Brute force protection |
| **Audit Logging** | Complete security event tracking |
| **Email Verification** | Secure email verification flow |

### OAuth2 Social Login
| Provider | Status |
|----------|--------|
| **Google** | ✅ Supported |
| **GitHub** | ✅ Supported |
| **Microsoft** | ✅ Supported |

### Passwordless Authentication
| Feature | Description |
|---------|-------------|
| **Magic Links** | Email-based passwordless login |
| **WebAuthn/Passkeys** | Hardware key & biometric auth |

### Role-Based Access Control (RBAC)
| Role | Permissions |
|------|-------------|
| **USER** | Basic profile access |
| **MODERATOR** | Content management |
| **ADMIN** | User management, audit logs |
| **SUPER_ADMIN** | Full system access |

### Security Features
| Feature | Description |
|---------|-------------|
| **IP Geolocation** | Detect logins from new countries |
| **Login Notifications** | Email/SMS/Push alerts |
| **Secure Admin API** | Cryptographic role verification |
| **API Key Auth** | For server-to-server communication |

## 🚀 Quick Start

### Prerequisites
- Node.js 20+
- Docker & Docker Compose
- PostgreSQL 16+
- Redis 7+

### 1. Clone & Install

```bash
git clone https://github.com/yourusername/auth-server.git
cd auth-server
npm install
```

### 2. Environment Setup

```bash
cp .env.example .env
# Edit .env with your values
```

### 3. Generate RSA Keys

```bash
npm run generate:keys
```

### 4. Start with Docker

```bash
# Development
docker-compose up -d

# Run migrations
npm run prisma:migrate

# Start dev server
npm run dev
```

### 5. Create Admin Account

```bash
# Create admin user
npx tsx scripts/create-admin.ts

# Sign the admin role (required for admin API access)
npx tsx scripts/sign-admin-role.ts
```

Default admin credentials:
- **Email:** `admin@example.com`
- **Password:** `Admin@123456!`

### 6. Access

- API: `http://localhost:3000`
- Prisma Studio: `http://localhost:5555`

### 7. Run Tests

```bash
npx tsx scripts/test-api.ts
```

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [Admin Setup Guide](docs/ADMIN-SETUP.md) | Creating and managing admin accounts |
| [API Reference](docs/API-REFERENCE.md) | Complete API documentation |
| [Environment Variables](.env.example) | All configuration options |

## 📡 API Endpoints

### Authentication
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/auth/register` | Register new user | ❌ |
| POST | `/api/v1/auth/login` | Login | ❌ |
| POST | `/api/v1/auth/logout` | Logout | ❌ |
| POST | `/api/v1/auth/refresh` | Refresh tokens | ❌ |
| GET | `/api/v1/auth/verify-email` | Verify email | ❌ |
| POST | `/api/v1/auth/forgot-password` | Request reset | ❌ |
| POST | `/api/v1/auth/reset-password` | Reset password | ❌ |
| GET | `/api/v1/auth/me` | Get current user | ✅ |
| POST | `/api/v1/auth/change-password` | Change password | ✅ |
| DELETE | `/api/v1/auth/sessions` | Revoke all sessions | ✅ |

### Two-Factor Authentication
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/auth/2fa/setup` | Get QR code | ✅ |
| POST | `/api/v1/auth/2fa/enable` | Enable 2FA | ✅ |
| POST | `/api/v1/auth/2fa/disable` | Disable 2FA | ✅ |
| POST | `/api/v1/auth/2fa/backup-codes` | Regenerate codes | ✅ |

### OAuth2 Social Login
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/auth/oauth/:provider` | Start OAuth flow | ❌ |
| GET | `/api/v1/auth/oauth/:provider/callback` | OAuth callback | ❌ |
| POST | `/api/v1/auth/oauth/:provider/link` | Link account | ✅ |
| DELETE | `/api/v1/auth/oauth/:provider/unlink` | Unlink account | ✅ |

### Passwordless Authentication
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/auth/passwordless/magic-link/request` | Request magic link | ❌ |
| POST | `/api/v1/auth/passwordless/magic-link/verify` | Verify magic link | ❌ |
| POST | `/api/v1/auth/passwordless/webauthn/register/options` | Get passkey options | ✅ |
| POST | `/api/v1/auth/passwordless/webauthn/register/verify` | Register passkey | ✅ |
| POST | `/api/v1/auth/passwordless/webauthn/login/options` | Get login options | ❌ |
| POST | `/api/v1/auth/passwordless/webauthn/login/verify` | Login with passkey | ❌ |

### API Keys
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| POST | `/api/v1/api-keys` | Create API key | ✅ |
| GET | `/api/v1/api-keys` | List API keys | ✅ |
| GET | `/api/v1/api-keys/:keyId` | Get API key | ✅ |
| PATCH | `/api/v1/api-keys/:keyId` | Update API key | ✅ |
| DELETE | `/api/v1/api-keys/:keyId` | Revoke API key | ✅ |
| POST | `/api/v1/api-keys/:keyId/rotate` | Rotate API key | ✅ |

### Admin API (Role-Verified)
| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/v1/admin/users` | List users | 🔒 Admin |
| GET | `/api/v1/admin/users/:userId` | Get user details | 🔒 Admin |
| PUT | `/api/v1/admin/users/:userId/role` | Update user role | 🔒 SuperAdmin |
| POST | `/api/v1/admin/users/:userId/lock` | Lock account | 🔒 Admin |
| POST | `/api/v1/admin/users/:userId/unlock` | Unlock account | 🔒 Admin |
| POST | `/api/v1/admin/users/:userId/reset-password` | Force reset | 🔒 SuperAdmin |
| GET | `/api/v1/admin/audit-logs` | View audit logs | 🔒 Admin |
| GET | `/api/v1/admin/stats` | System stats | 🔒 Admin |

## 🔒 Admin Security

The Admin API uses **triple verification** to prevent role manipulation attacks:

1. **Database Verification** - Role is ALWAYS fetched from database, never trusted from JWT
2. **Cryptographic Signature** - Admin roles have HMAC signatures that are verified
3. **Signature Expiry** - Role signatures expire and must be refreshed

This means even if an attacker intercepts a request and modifies the role claim, the server will:
- Verify the role against the database
- Check the cryptographic signature
- Reject the request if verification fails
- Log the attempt as suspicious activity

## 🔧 Usage Examples

### Register
```bash
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ss123!",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

### Login
```bash
curl -X POST http://localhost:3000/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecureP@ss123!"
  }'
```

### Using API Key
```bash
curl http://localhost:3000/api/v1/some-endpoint \
  -H "X-API-Key: ak_your_api_key_here"
```

## 🐳 Production Deployment

### 1. Prepare Environment
```bash
cp .env.prod.example .env.prod
# Edit with production values
```

### 2. Generate SSL Certificates
```bash
mkdir -p docker/nginx/certs
# Add your SSL certificates:
# - docker/nginx/certs/fullchain.pem
# - docker/nginx/certs/privkey.pem
```

### 3. Deploy
```bash
docker-compose -f docker-compose.prod.yml --env-file .env.prod up -d
```

## 📁 Project Structure

```
auth/
├── src/
│   ├── config/          # Configuration
│   │   ├── index.ts     # Main config
│   │   ├── rbac.ts      # Role permissions
│   │   └── roleSignature.ts  # Admin security
│   ├── controllers/     # Route handlers
│   │   ├── admin.controller.ts
│   │   ├── apiKey.controller.ts
│   │   ├── auth.controller.ts
│   │   ├── oauth.controller.ts
│   │   ├── passwordless.controller.ts
│   │   └── twoFactor.controller.ts
│   ├── middleware/      # Express middleware
│   │   ├── apiKey.middleware.ts
│   │   ├── auth.middleware.ts
│   │   ├── rbac.middleware.ts
│   │   ├── rateLimit.middleware.ts
│   │   └── validate.middleware.ts
│   ├── routes/          # API routes
│   ├── services/        # Business logic
│   │   ├── audit.service.ts
│   │   ├── email.service.ts
│   │   ├── geolocation.service.ts
│   │   ├── magicLink.service.ts
│   │   ├── notification.service.ts
│   │   ├── oauth.service.ts
│   │   └── webauthn.service.ts
│   ├── utils/           # Utilities
│   └── server.ts        # Entry point
├── prisma/
│   └── schema.prisma    # Database schema
├── docker/nginx/        # Nginx config
├── Dockerfile
├── docker-compose.yml
└── docker-compose.prod.yml
```

## 🔑 Environment Variables

See `.env.example` for all available options including:
- Server configuration
- Database & Redis
- JWT settings
- OAuth2 providers (Google, GitHub, Microsoft)
- WebAuthn/Passkeys
- Email (SMTP)
- SMS (Twilio)
- Push notifications (Firebase)

## 📄 License

MIT License - See [LICENSE](LICENSE) for details.

---

**⚠️ Security Notice:** Always use HTTPS in production. Keep your RSA keys, API keys, and `.env` files secure and never commit them to version control.

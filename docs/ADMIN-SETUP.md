# Admin Account Setup Guide

This guide explains how to create and manage admin accounts in the Enterprise Auth Server.

## Quick Setup (First Time)

### 1. Create Admin User

Run the admin creation script:

```bash
npx tsx scripts/create-admin.ts
```

This creates a default admin with:
- **Email:** `admin@example.com`
- **Password:** `Admin@123456!`
- **Role:** `SUPER_ADMIN`

### 2. Sign the Admin Role

For security, admin roles require cryptographic signatures. Run:

```bash
npx tsx scripts/sign-admin-role.ts
```

This generates a signature that expires in 30 days.

### 3. Verify Admin Access

```bash
# Login
$login = Invoke-RestMethod -Uri "http://localhost:3000/api/v1/auth/login" -Method POST -ContentType "application/json" -Body '{"email":"admin@example.com","password":"Admin@123456!"}'

# Get stats
$token = $login.data.accessToken
Invoke-RestMethod -Uri "http://localhost:3000/api/v1/admin/stats" -Headers @{"Authorization"="Bearer $token"}
```

---

## Custom Admin Creation

### Create Custom Admin

Edit `scripts/create-admin.ts` or use the API:

```bash
# 1. Register user via API
curl -X POST http://localhost:3000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"newadmin@company.com","password":"SecurePass@123!","firstName":"John","lastName":"Doe"}'

# 2. Update role in database
docker exec auth-postgres-dev psql -U postgres -d auth_db -c "UPDATE \"User\" SET role = 'SUPER_ADMIN' WHERE email = 'newadmin@company.com';"

# 3. Sign the role
npx tsx scripts/sign-admin-role.ts newadmin@company.com
```

---

## Role Hierarchy

| Role | Level | Permissions |
|------|-------|-------------|
| `USER` | 1 | Profile access, own sessions |
| `MODERATOR` | 2 | + Content management, view users |
| `ADMIN` | 3 | + User management, audit logs |
| `SUPER_ADMIN` | 4 | + Role management, system config |

---

## Security Features

### Triple Verification for Admin Access

1. **Database Check** - Role is ALWAYS fetched from database, never trusted from JWT
2. **Signature Verification** - Cryptographic HMAC signature must be valid
3. **Expiry Check** - Signature must not be expired

### Why Role Signatures?

Even if an attacker:
- Intercepts a request and changes the role claim
- Modifies the database directly
- Steals an admin token

They **cannot** bypass the cryptographic signature because:
- Signature is tied to user ID + role + timestamp
- Signature uses a server-side secret
- Invalid signature = request rejected + audit logged

---

## Available Scripts

| Script | Purpose |
|--------|---------|
| `scripts/create-admin.ts` | Create default admin account |
| `scripts/sign-admin-role.ts` | Sign/refresh admin role signature |
| `scripts/test-api.ts` | Run comprehensive API tests |

---

## Troubleshooting

### "Role verification failed" Error

The admin's role signature is missing or expired. Fix:

```bash
npx tsx scripts/sign-admin-role.ts admin@example.com
```

### "Missing role signature" Error

Same as above - run the sign script.

### "Role mismatch" Error

The user's role in database doesn't match their claim. Check database:

```bash
docker exec auth-postgres-dev psql -U postgres -d auth_db -c "SELECT email, role FROM \"User\";"
```

### Can't Login as Admin

1. Verify the user exists
2. Check password is correct
3. Ensure emailVerified is true in database

---

## Production Recommendations

1. **Change default password** immediately after setup
2. **Use strong secrets** in `.env` for `ROLE_SIGNATURE_SECRET`
3. **Set shorter expiry** for role signatures (e.g., 24 hours)
4. **Enable 2FA** on all admin accounts
5. **Monitor audit logs** for suspicious admin activity
6. **Use separate super admin** for critical operations only

---

## API Endpoints for Admin

### System
- `GET /api/v1/admin/stats` - System statistics
- `GET /api/v1/admin/audit-logs` - Audit logs

### User Management
- `GET /api/v1/admin/users` - List all users
- `GET /api/v1/admin/users/:id` - Get user details
- `PUT /api/v1/admin/users/:id/role` - Change user role
- `POST /api/v1/admin/users/:id/lock` - Lock user account
- `POST /api/v1/admin/users/:id/unlock` - Unlock user account
- `POST /api/v1/admin/users/:id/reset-password` - Force password reset (SUPER_ADMIN only)

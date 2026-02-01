import swaggerJsdoc from 'swagger-jsdoc';

const options: swaggerJsdoc.Options = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: '🔐 Enterprise Auth Server API',
            version: '1.0.0',
            description: `
## Military-Grade Authentication API

A production-ready authentication server with enterprise security features.

### Features
- **JWT RS256** - Asymmetric token signing with RSA-4096
- **Two-Factor Auth** - TOTP with backup codes
- **OAuth2** - Google, GitHub, Microsoft
- **Passwordless** - Magic Links & WebAuthn/Passkeys
- **RBAC** - Role-Based Access Control
- **API Keys** - Server-to-server authentication
- **Audit Logging** - Complete security event tracking

### Authentication
Most endpoints require authentication via Bearer token:
\`\`\`
Authorization: Bearer <access_token>
\`\`\`

Or via API Key:
\`\`\`
X-API-Key: ak_your_api_key
\`\`\`
            `,
            contact: {
                name: 'API Support',
                email: 'support@example.com',
            },
            license: {
                name: 'MIT',
                url: 'https://opensource.org/licenses/MIT',
            },
        },
        servers: [
            {
                url: 'http://localhost:3000/api/v1',
                description: 'Development server',
            },
            {
                url: 'https://api.example.com/api/v1',
                description: 'Production server',
            },
        ],
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                    description: 'JWT access token',
                },
                apiKey: {
                    type: 'apiKey',
                    in: 'header',
                    name: 'X-API-Key',
                    description: 'API key for server-to-server communication',
                },
            },
            schemas: {
                User: {
                    type: 'object',
                    properties: {
                        id: { type: 'string', format: 'uuid' },
                        email: { type: 'string', format: 'email' },
                        firstName: { type: 'string' },
                        lastName: { type: 'string' },
                        role: { type: 'string', enum: ['USER', 'MODERATOR', 'ADMIN', 'SUPER_ADMIN'] },
                        isVerified: { type: 'boolean' },
                        twoFactorEnabled: { type: 'boolean' },
                        createdAt: { type: 'string', format: 'date-time' },
                    },
                },
                LoginRequest: {
                    type: 'object',
                    required: ['email', 'password'],
                    properties: {
                        email: { type: 'string', format: 'email', example: 'admin@example.com' },
                        password: { type: 'string', minLength: 8, example: 'Admin@123456!' },
                        twoFactorCode: { type: 'string', pattern: '^[0-9]{6}$', example: '123456' },
                    },
                },
                RegisterRequest: {
                    type: 'object',
                    required: ['email', 'password'],
                    properties: {
                        email: { type: 'string', format: 'email', example: 'user@example.com' },
                        password: { type: 'string', minLength: 8, example: 'SecurePass@123!' },
                        firstName: { type: 'string', example: 'John' },
                        lastName: { type: 'string', example: 'Doe' },
                    },
                },
                AuthResponse: {
                    type: 'object',
                    properties: {
                        success: { type: 'boolean' },
                        data: {
                            type: 'object',
                            properties: {
                                accessToken: { type: 'string' },
                                user: { $ref: '#/components/schemas/User' },
                            },
                        },
                    },
                },
                ErrorResponse: {
                    type: 'object',
                    properties: {
                        success: { type: 'boolean', example: false },
                        error: {
                            type: 'object',
                            properties: {
                                code: { type: 'string', example: 'UNAUTHORIZED' },
                                message: { type: 'string', example: 'Invalid credentials' },
                            },
                        },
                    },
                },
                StatsResponse: {
                    type: 'object',
                    properties: {
                        success: { type: 'boolean' },
                        data: {
                            type: 'object',
                            properties: {
                                users: {
                                    type: 'object',
                                    properties: {
                                        total: { type: 'integer' },
                                        verified: { type: 'integer' },
                                        with2FA: { type: 'integer' },
                                    },
                                },
                                sessions: {
                                    type: 'object',
                                    properties: {
                                        active: { type: 'integer' },
                                    },
                                },
                            },
                        },
                    },
                },
            },
        },
        tags: [
            { name: 'Authentication', description: 'User authentication endpoints' },
            { name: 'Two-Factor Auth', description: '2FA setup and verification' },
            { name: 'OAuth2', description: 'Social login providers' },
            { name: 'Passwordless', description: 'Magic links and WebAuthn' },
            { name: 'API Keys', description: 'API key management' },
            { name: 'Admin', description: 'Admin-only operations' },
        ],
        paths: {
            '/auth/register': {
                post: {
                    tags: ['Authentication'],
                    summary: 'Register a new user',
                    description: 'Create a new user account with email and password',
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: { $ref: '#/components/schemas/RegisterRequest' },
                            },
                        },
                    },
                    responses: {
                        '201': {
                            description: 'User registered successfully',
                            content: {
                                'application/json': {
                                    schema: { $ref: '#/components/schemas/AuthResponse' },
                                },
                            },
                        },
                        '400': {
                            description: 'Invalid request data',
                            content: {
                                'application/json': {
                                    schema: { $ref: '#/components/schemas/ErrorResponse' },
                                },
                            },
                        },
                        '409': {
                            description: 'Email already exists',
                        },
                    },
                },
            },
            '/auth/login': {
                post: {
                    tags: ['Authentication'],
                    summary: 'Login with email and password',
                    description: 'Authenticate user and receive access token',
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: { $ref: '#/components/schemas/LoginRequest' },
                            },
                        },
                    },
                    responses: {
                        '200': {
                            description: 'Login successful',
                            content: {
                                'application/json': {
                                    schema: { $ref: '#/components/schemas/AuthResponse' },
                                },
                            },
                        },
                        '401': {
                            description: 'Invalid credentials',
                        },
                        '403': {
                            description: 'Account locked or requires 2FA',
                        },
                    },
                },
            },
            '/auth/me': {
                get: {
                    tags: ['Authentication'],
                    summary: 'Get current user profile',
                    security: [{ bearerAuth: [] }],
                    responses: {
                        '200': {
                            description: 'User profile',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean' },
                                            data: { $ref: '#/components/schemas/User' },
                                        },
                                    },
                                },
                            },
                        },
                        '401': { description: 'Unauthorized' },
                    },
                },
            },
            '/auth/logout': {
                post: {
                    tags: ['Authentication'],
                    summary: 'Logout and invalidate tokens',
                    responses: {
                        '200': { description: 'Logged out successfully' },
                    },
                },
            },
            '/auth/refresh': {
                post: {
                    tags: ['Authentication'],
                    summary: 'Refresh access token',
                    description: 'Get new access token using refresh token cookie',
                    responses: {
                        '200': {
                            description: 'New access token',
                            content: {
                                'application/json': {
                                    schema: { $ref: '#/components/schemas/AuthResponse' },
                                },
                            },
                        },
                    },
                },
            },
            '/auth/change-password': {
                post: {
                    tags: ['Authentication'],
                    summary: 'Change password',
                    security: [{ bearerAuth: [] }],
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    required: ['currentPassword', 'newPassword'],
                                    properties: {
                                        currentPassword: { type: 'string' },
                                        newPassword: { type: 'string', minLength: 8 },
                                    },
                                },
                            },
                        },
                    },
                    responses: {
                        '200': { description: 'Password changed' },
                        '401': { description: 'Current password incorrect' },
                    },
                },
            },
            '/auth/forgot-password': {
                post: {
                    tags: ['Authentication'],
                    summary: 'Request password reset',
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    required: ['email'],
                                    properties: {
                                        email: { type: 'string', format: 'email' },
                                    },
                                },
                            },
                        },
                    },
                    responses: {
                        '200': { description: 'Reset email sent (if user exists)' },
                    },
                },
            },
            '/auth/reset-password': {
                post: {
                    tags: ['Authentication'],
                    summary: 'Reset password with token',
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    required: ['token', 'password'],
                                    properties: {
                                        token: { type: 'string' },
                                        password: { type: 'string', minLength: 8 },
                                    },
                                },
                            },
                        },
                    },
                    responses: {
                        '200': { description: 'Password reset successful' },
                        '400': { description: 'Invalid or expired token' },
                    },
                },
            },
            '/auth/2fa/setup': {
                post: {
                    tags: ['Two-Factor Auth'],
                    summary: 'Setup 2FA',
                    description: 'Get QR code and secret for TOTP setup',
                    security: [{ bearerAuth: [] }],
                    responses: {
                        '200': {
                            description: '2FA setup data',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean' },
                                            data: {
                                                type: 'object',
                                                properties: {
                                                    qrCode: { type: 'string', description: 'Base64 QR code image' },
                                                    secret: { type: 'string', description: 'TOTP secret' },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            '/auth/2fa/enable': {
                post: {
                    tags: ['Two-Factor Auth'],
                    summary: 'Enable 2FA',
                    security: [{ bearerAuth: [] }],
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    required: ['code'],
                                    properties: {
                                        code: { type: 'string', pattern: '^[0-9]{6}$' },
                                    },
                                },
                            },
                        },
                    },
                    responses: {
                        '200': {
                            description: '2FA enabled with backup codes',
                            content: {
                                'application/json': {
                                    schema: {
                                        type: 'object',
                                        properties: {
                                            success: { type: 'boolean' },
                                            data: {
                                                type: 'object',
                                                properties: {
                                                    backupCodes: { type: 'array', items: { type: 'string' } },
                                                },
                                            },
                                        },
                                    },
                                },
                            },
                        },
                    },
                },
            },
            '/auth/2fa/disable': {
                post: {
                    tags: ['Two-Factor Auth'],
                    summary: 'Disable 2FA',
                    security: [{ bearerAuth: [] }],
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    required: ['code'],
                                    properties: {
                                        code: { type: 'string' },
                                    },
                                },
                            },
                        },
                    },
                    responses: {
                        '200': { description: '2FA disabled' },
                    },
                },
            },
            '/oauth/google': {
                get: {
                    tags: ['OAuth2'],
                    summary: 'Initiate Google OAuth',
                    description: 'Redirects to Google login',
                    responses: {
                        '302': { description: 'Redirect to Google' },
                    },
                },
            },
            '/oauth/github': {
                get: {
                    tags: ['OAuth2'],
                    summary: 'Initiate GitHub OAuth',
                    responses: {
                        '302': { description: 'Redirect to GitHub' },
                    },
                },
            },
            '/oauth/microsoft': {
                get: {
                    tags: ['OAuth2'],
                    summary: 'Initiate Microsoft OAuth',
                    responses: {
                        '302': { description: 'Redirect to Microsoft' },
                    },
                },
            },
            '/passwordless/magic-link/request': {
                post: {
                    tags: ['Passwordless'],
                    summary: 'Request magic link',
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    required: ['email'],
                                    properties: {
                                        email: { type: 'string', format: 'email' },
                                    },
                                },
                            },
                        },
                    },
                    responses: {
                        '200': { description: 'Magic link sent' },
                    },
                },
            },
            '/passwordless/magic-link/verify': {
                post: {
                    tags: ['Passwordless'],
                    summary: 'Verify magic link',
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    required: ['token'],
                                    properties: {
                                        token: { type: 'string' },
                                    },
                                },
                            },
                        },
                    },
                    responses: {
                        '200': {
                            description: 'Login successful',
                            content: {
                                'application/json': {
                                    schema: { $ref: '#/components/schemas/AuthResponse' },
                                },
                            },
                        },
                    },
                },
            },
            '/api-keys': {
                get: {
                    tags: ['API Keys'],
                    summary: 'List API keys',
                    security: [{ bearerAuth: [] }],
                    responses: {
                        '200': { description: 'List of API keys' },
                    },
                },
                post: {
                    tags: ['API Keys'],
                    summary: 'Create API key',
                    security: [{ bearerAuth: [] }],
                    requestBody: {
                        required: true,
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    required: ['name'],
                                    properties: {
                                        name: { type: 'string', example: 'My API Key' },
                                        scopes: { type: 'array', items: { type: 'string' } },
                                        expiresInDays: { type: 'integer', example: 30 },
                                    },
                                },
                            },
                        },
                    },
                    responses: {
                        '201': { description: 'API key created' },
                    },
                },
            },
            '/admin/stats': {
                get: {
                    tags: ['Admin'],
                    summary: 'Get system statistics',
                    security: [{ bearerAuth: [] }],
                    responses: {
                        '200': {
                            description: 'System stats',
                            content: {
                                'application/json': {
                                    schema: { $ref: '#/components/schemas/StatsResponse' },
                                },
                            },
                        },
                        '403': { description: 'Requires admin role' },
                    },
                },
            },
            '/admin/users': {
                get: {
                    tags: ['Admin'],
                    summary: 'List all users',
                    security: [{ bearerAuth: [] }],
                    parameters: [
                        { name: 'page', in: 'query', schema: { type: 'integer', default: 1 } },
                        { name: 'limit', in: 'query', schema: { type: 'integer', default: 20 } },
                    ],
                    responses: {
                        '200': { description: 'Paginated user list' },
                    },
                },
            },
            '/admin/audit-logs': {
                get: {
                    tags: ['Admin'],
                    summary: 'Get audit logs',
                    security: [{ bearerAuth: [] }],
                    parameters: [
                        { name: 'limit', in: 'query', schema: { type: 'integer', default: 50 } },
                        { name: 'userId', in: 'query', schema: { type: 'string' } },
                        { name: 'action', in: 'query', schema: { type: 'string' } },
                    ],
                    responses: {
                        '200': { description: 'Audit log entries' },
                    },
                },
            },
        },
    },
    apis: [], // We define everything inline above
};

export const swaggerSpec = swaggerJsdoc(options);

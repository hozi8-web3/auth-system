import express, { Request, Response, NextFunction } from 'express';
import cors from 'cors';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import config, { validateConfig } from './config/index.js';
import { connectDatabase, disconnectDatabase } from './config/database.js';
import { connectRedis, disconnectRedis } from './config/redis.js';
import { generalLimiter } from './middleware/rateLimit.middleware.js';
import authRoutes from './routes/auth.routes.js';
import oauthRoutes from './routes/oauth.routes.js';
import adminRoutes from './routes/admin.routes.js';
import apiKeyRoutes from './routes/apiKey.routes.js';
import passwordlessRoutes from './routes/passwordless.routes.js';

// ============================================
// VALIDATE CONFIGURATION
// ============================================

validateConfig();

// ============================================
// CREATE EXPRESS APP
// ============================================

const app = express();

// ============================================
// SECURITY MIDDLEWARE
// ============================================

// Helmet security headers
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'"],
                styleSrc: ["'self'", "'unsafe-inline'"],
                imgSrc: ["'self'", 'data:', 'https:'],
                connectSrc: ["'self'"],
                fontSrc: ["'self'"],
                objectSrc: ["'none'"],
                mediaSrc: ["'self'"],
                frameSrc: ["'none'"],
            },
        },
        crossOriginEmbedderPolicy: true,
        crossOriginOpenerPolicy: true,
        crossOriginResourcePolicy: { policy: 'same-origin' },
        dnsPrefetchControl: { allow: false },
        frameguard: { action: 'deny' },
        hidePoweredBy: true,
        hsts: {
            maxAge: 31536000,
            includeSubDomains: true,
            preload: true,
        },
        ieNoOpen: true,
        noSniff: true,
        originAgentCluster: true,
        permittedCrossDomainPolicies: { permittedPolicies: 'none' },
        referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
        xssFilter: true,
    })
);

// CORS
app.use(
    cors({
        origin: (origin, callback) => {
            // Allow requests with no origin (mobile apps, curl, etc.)
            if (!origin) {
                callback(null, true);
                return;
            }

            if (config.cors.origins.includes(origin)) {
                callback(null, true);
            } else {
                callback(new Error('Not allowed by CORS'));
            }
        },
        credentials: true,
        methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With', 'X-API-Key'],
        exposedHeaders: ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'X-RateLimit-Reset'],
        maxAge: 86400, // 24 hours
    })
);

// ============================================
// BODY PARSING
// ============================================

app.use(express.json({ limit: '10kb' })); // Limit body size
app.use(express.urlencoded({ extended: true, limit: '10kb' }));
app.use(cookieParser());

// ============================================
// RATE LIMITING
// ============================================

app.use(generalLimiter);

// ============================================
// TRUST PROXY (for rate limiting behind reverse proxy)
// ============================================

app.set('trust proxy', 1);

// ============================================
// HEALTH CHECK
// ============================================

app.get('/health', (_req: Request, res: Response) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        version: process.env.npm_package_version || '1.0.0',
    });
});

// ============================================
// API ROUTES
// ============================================

const apiPrefix = `/api/${config.apiVersion}`;

// Core authentication routes
app.use(`${apiPrefix}/auth`, authRoutes);

// OAuth routes (Google, GitHub, Microsoft)
app.use(`${apiPrefix}/auth/oauth`, oauthRoutes);

// Passwordless routes (Magic Link, WebAuthn)
app.use(`${apiPrefix}/auth/passwordless`, passwordlessRoutes);

// API Key management
app.use(`${apiPrefix}/api-keys`, apiKeyRoutes);

// Admin routes (secure, role-verified)
app.use(`${apiPrefix}/admin`, adminRoutes);

// ============================================
// 404 HANDLER
// ============================================

app.use((_req: Request, res: Response) => {
    res.status(404).json({
        success: false,
        error: 'Endpoint not found',
        code: 'NOT_FOUND',
    });
});

// ============================================
// ERROR HANDLER
// ============================================

app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
    console.error('Unhandled error:', err);

    // Don't leak error details in production
    const message =
        config.env === 'production' ? 'Internal server error' : err.message;

    res.status(500).json({
        success: false,
        error: message,
        code: 'INTERNAL_ERROR',
    });
});

// ============================================
// START SERVER
// ============================================

async function start(): Promise<void> {
    try {
        // Connect to database
        await connectDatabase();

        // Connect to Redis
        await connectRedis();

        // Start server
        const server = app.listen(config.port, () => {
            console.log(`
╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   🔐 Enterprise Auth Server                                    ║
║                                                                ║
║   Environment: ${config.env.padEnd(45)}║
║   Port: ${config.port.toString().padEnd(52)}║
║   API Version: ${config.apiVersion.padEnd(44)}║
║                                                                ║
║   Endpoints:                                                   ║
║   • POST /api/${config.apiVersion}/auth/register                              ║
║   • POST /api/${config.apiVersion}/auth/login                                 ║
║   • POST /api/${config.apiVersion}/auth/logout                                ║
║   • POST /api/${config.apiVersion}/auth/refresh                               ║
║   • GET  /api/${config.apiVersion}/auth/verify-email                          ║
║   • POST /api/${config.apiVersion}/auth/forgot-password                       ║
║   • POST /api/${config.apiVersion}/auth/reset-password                        ║
║   • GET  /api/${config.apiVersion}/auth/me                                    ║
║   • POST /api/${config.apiVersion}/auth/2fa/setup                             ║
║   • POST /api/${config.apiVersion}/auth/2fa/enable                            ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝
      `);
        });

        // Graceful shutdown
        const shutdown = async (signal: string) => {
            console.log(`\n${signal} received. Shutting down gracefully...`);

            server.close(async () => {
                await disconnectDatabase();
                await disconnectRedis();
                console.log('Server closed.');
                process.exit(0);
            });

            // Force exit if graceful shutdown takes too long
            setTimeout(() => {
                console.error('Forced shutdown after timeout');
                process.exit(1);
            }, 10000);
        };

        process.on('SIGTERM', () => shutdown('SIGTERM'));
        process.on('SIGINT', () => shutdown('SIGINT'));
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
}

start();

export default app;

import { PrismaClient } from '@prisma/client';
import config from './index.js';

// ============================================
// PRISMA CLIENT SINGLETON
// ============================================

declare global {
    // eslint-disable-next-line no-var
    var prisma: PrismaClient | undefined;
}

export const prisma =
    global.prisma ||
    new PrismaClient({
        log: config.env === 'development' ? ['query', 'error', 'warn'] : ['error'],
        errorFormat: 'pretty',
    });

if (config.env !== 'production') {
    global.prisma = prisma;
}

// ============================================
// CONNECTION MANAGEMENT
// ============================================

export async function connectDatabase(): Promise<void> {
    try {
        await prisma.$connect();
        console.log('✅ Database connected successfully');
    } catch (error) {
        console.error('❌ Database connection failed:', error);
        process.exit(1);
    }
}

export async function disconnectDatabase(): Promise<void> {
    await prisma.$disconnect();
    console.log('📤 Database disconnected');
}

export default prisma;

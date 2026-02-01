import { PrismaClient } from '@prisma/client';
import crypto from 'crypto';

const prisma = new PrismaClient();

const ROLE_SIGNATURE_SECRET = process.env.ROLE_SIGNATURE_SECRET || 'auth.localhost-role-secret';
const ROLE_SIGNATURE_VALIDITY_HOURS = 24 * 30; // 30 days for initial setup

function generateRoleSignature(userId: string, role: string): string {
    const timestamp = Date.now();
    const data = `${userId}:${role}:${timestamp}`;
    const signature = crypto
        .createHmac('sha256', ROLE_SIGNATURE_SECRET)
        .update(data)
        .digest('hex');
    return `${timestamp}:${signature}`;
}

async function signAdminRole() {
    const email = process.argv[2] || 'admin@example.com';

    const user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        console.log('❌ User not found:', email);
        await prisma.$disconnect();
        return;
    }

    const signature = generateRoleSignature(user.id, user.role);
    const expiry = new Date();
    expiry.setHours(expiry.getHours() + ROLE_SIGNATURE_VALIDITY_HOURS);

    await prisma.user.update({
        where: { id: user.id },
        data: {
            roleSignature: signature,
            roleSignatureExpiry: expiry,
            roleAssignedAt: new Date(),
            roleAssignedBy: 'SYSTEM',
        },
    });

    console.log('✅ Role signature assigned!');
    console.log('📧 Email:', email);
    console.log('👤 Role:', user.role);
    console.log('⏰ Expires:', expiry.toISOString());

    await prisma.$disconnect();
}

signAdminRole().catch((e) => {
    console.error(e);
    prisma.$disconnect();
});

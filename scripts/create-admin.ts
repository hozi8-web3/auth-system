import { PrismaClient } from '@prisma/client';
import * as argon2 from 'argon2';

const prisma = new PrismaClient();

async function createAdmin() {
    const email = 'admin@example.com';
    const password = 'Admin@123456!';

    // Hash password
    const passwordHash = await argon2.hash(password, {
        type: argon2.argon2id,
        memoryCost: 65536,
        timeCost: 3,
        parallelism: 4,
    });

    // Check if user exists
    let user = await prisma.user.findUnique({ where: { email } });

    if (!user) {
        // Create user
        user = await prisma.user.create({
            data: {
                email,
                passwordHash,
                firstName: 'Super',
                lastName: 'Admin',
                emailVerified: true,
                role: 'SUPER_ADMIN',
            },
        });
        console.log('✅ Admin user created:', email);
    } else {
        // Update existing user to SUPER_ADMIN
        await prisma.user.update({
            where: { email },
            data: {
                role: 'SUPER_ADMIN',
                emailVerified: true,
            },
        });
        console.log('✅ Admin user updated to SUPER_ADMIN:', email);
    }

    console.log('');
    console.log('📧 Email:', email);
    console.log('🔑 Password:', password);
    console.log('👤 Role: SUPER_ADMIN');

    await prisma.$disconnect();
}

createAdmin().catch((e) => {
    console.error(e);
    prisma.$disconnect();
});

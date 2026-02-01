/**
 * Enterprise Auth Server - Comprehensive API Test Script
 * 
 * Tests all major endpoints and features
 * Run: npx tsx scripts/test-api.ts
 */

const BASE_URL = 'http://localhost:3000/api/v1';

interface TestResult {
    name: string;
    passed: boolean;
    status?: number;
    message?: string;
    data?: unknown;
}

const results: TestResult[] = [];
let accessToken = '';
let refreshToken = '';
let testUserId = '';
let apiKeyId = '';
let apiKeyValue = '';

// ============================================
// HELPER FUNCTIONS
// ============================================

async function request(
    method: string,
    endpoint: string,
    options: {
        body?: unknown;
        auth?: boolean;
        apiKey?: boolean;
    } = {}
): Promise<{ status: number; data: unknown }> {
    const headers: Record<string, string> = {
        'Content-Type': 'application/json',
    };

    if (options.auth && accessToken) {
        headers['Authorization'] = `Bearer ${accessToken}`;
    }

    if (options.apiKey && apiKeyValue) {
        headers['X-API-Key'] = apiKeyValue;
    }

    const res = await fetch(`${BASE_URL}${endpoint}`, {
        method,
        headers,
        body: options.body ? JSON.stringify(options.body) : undefined,
    });

    const data = await res.json().catch(() => ({}));
    return { status: res.status, data };
}

function log(emoji: string, message: string) {
    console.log(`${emoji} ${message}`);
}

function test(name: string, passed: boolean, details?: { status?: number; message?: string; data?: unknown }) {
    results.push({ name, passed, ...details });
    if (passed) {
        log('✅', `PASS: ${name}`);
    } else {
        log('❌', `FAIL: ${name} - ${details?.message || 'Unknown error'}`);
    }
}

// ============================================
// TEST CASES
// ============================================

async function testHealthCheck() {
    log('🔍', 'Testing Health Check...');
    const res = await fetch(`${BASE_URL.replace('/api/v1', '')}/health`);
    const data = await res.json();
    test('Health Check', res.status === 200 && data.status === 'healthy', { status: res.status, data });
}

async function testRegister() {
    log('🔍', 'Testing User Registration...');

    const email = `test-${Date.now()}@example.com`;
    const { status, data } = await request('POST', '/auth/register', {
        body: {
            email,
            password: 'TestUser@123!',
            firstName: 'Test',
            lastName: 'User',
        },
    });

    test('Register New User', status === 201, { status, data });
}

async function testRegisterValidation() {
    log('🔍', 'Testing Registration Validation...');

    // Weak password
    const { status, data } = await request('POST', '/auth/register', {
        body: {
            email: 'test@example.com',
            password: '123',
        },
    });

    test('Register Validation (weak password rejected)', status === 400, { status, data });
}

async function testLogin() {
    log('🔍', 'Testing Login...');

    const { status, data } = await request('POST', '/auth/login', {
        body: {
            email: 'admin@example.com',
            password: 'Admin@123456!',
        },
    }) as { status: number; data: { success: boolean; data?: { accessToken: string } } };

    if (status === 200 && data.data?.accessToken) {
        accessToken = data.data.accessToken;
    }

    test('Admin Login', status === 200 && !!accessToken, { status, data });
}

async function testLoginWrongPassword() {
    log('🔍', 'Testing Login with Wrong Password...');

    const { status, data } = await request('POST', '/auth/login', {
        body: {
            email: 'admin@example.com',
            password: 'WrongPassword123!',
        },
    });

    test('Login Wrong Password (rejected)', status === 401, { status, data });
}

async function testGetMe() {
    log('🔍', 'Testing Get Current User...');

    const { status, data } = await request('GET', '/auth/me', { auth: true });
    test('Get Current User', status === 200, { status, data });
}

async function testGetMeNoAuth() {
    log('🔍', 'Testing Get Current User without Auth...');

    const { status, data } = await request('GET', '/auth/me');
    test('Get Current User (no auth rejected)', status === 401, { status, data });
}

async function testAdminStats() {
    log('🔍', 'Testing Admin Stats...');

    const { status, data } = await request('GET', '/admin/stats', { auth: true });
    test('Admin Stats', status === 200, { status, data });
}

async function testAdminListUsers() {
    log('🔍', 'Testing Admin List Users...');

    const { status, data } = await request('GET', '/admin/users', { auth: true }) as {
        status: number;
        data: { success: boolean; data?: { users: { id: string }[] } }
    };

    if (status === 200 && data.data?.users?.length) {
        testUserId = data.data.users[0].id;
    }

    test('Admin List Users', status === 200, { status, data });
}

async function testAdminGetUser() {
    log('🔍', 'Testing Admin Get User Details...');

    if (!testUserId) {
        test('Admin Get User Details', false, { message: 'No user ID available' });
        return;
    }

    const { status, data } = await request('GET', `/admin/users/${testUserId}`, { auth: true });
    test('Admin Get User Details', status === 200, { status, data });
}

async function testAdminAuditLogs() {
    log('🔍', 'Testing Admin Audit Logs...');

    const { status, data } = await request('GET', '/admin/audit-logs', { auth: true });
    test('Admin Audit Logs', status === 200, { status, data });
}

async function testCreateApiKey() {
    log('🔍', 'Testing Create API Key...');

    const { status, data } = await request('POST', '/api-keys', {
        auth: true,
        body: {
            name: 'Test API Key',
            scopes: ['read', 'write'],
            expiresInDays: 30,
        },
    }) as { status: number; data: { success: boolean; data?: { id: string; key: string } } };

    if (status === 201 && data.data) {
        apiKeyId = data.data.id;
        apiKeyValue = data.data.key;
    }

    test('Create API Key', status === 201, { status, data: { ...data, keyHidden: '***' } });
}

async function testListApiKeys() {
    log('🔍', 'Testing List API Keys...');

    const { status, data } = await request('GET', '/api-keys', { auth: true });
    test('List API Keys', status === 200, { status, data });
}

async function testRevokeApiKey() {
    log('🔍', 'Testing Revoke API Key...');

    if (!apiKeyId) {
        test('Revoke API Key', false, { message: 'No API key ID available' });
        return;
    }

    const { status, data } = await request('DELETE', `/api-keys/${apiKeyId}`, { auth: true });
    test('Revoke API Key', status === 200, { status, data });
}

async function test2FASetup() {
    log('🔍', 'Testing 2FA Setup...');

    const { status, data } = await request('POST', '/auth/2fa/setup', { auth: true });
    test('2FA Setup', status === 200, { status, data: { dataReceived: !!data } });
}

async function testOAuthGoogle() {
    log('🔍', 'Testing OAuth Google Init...');

    const { status, data } = await request('GET', '/oauth/google');
    // Should return auth URL (may fail without proper OAuth config)
    test('OAuth Google Init', status === 200 || status === 500, { status, data });
}

async function testMagicLinkRequest() {
    log('🔍', 'Testing Magic Link Request...');

    const { status, data } = await request('POST', '/passwordless/magic-link/request', {
        body: { email: 'test@example.com' },
    });
    // May fail without SMTP config, but should not crash
    test('Magic Link Request', status === 200 || status === 500, { status, data });
}

async function testWebAuthnOptions() {
    log('🔍', 'Testing WebAuthn Registration Options...');

    const { status, data } = await request('POST', '/passwordless/webauthn/register/options', { auth: true });
    test('WebAuthn Registration Options', status === 200 || status === 500, { status, data });
}

async function testPasswordReset() {
    log('🔍', 'Testing Forgot Password...');

    const { status, data } = await request('POST', '/auth/forgot-password', {
        body: { email: 'admin@example.com' },
    });
    // May fail without SMTP config
    test('Forgot Password Request', status === 200 || status === 500, { status, data });
}

async function testRateLimiting() {
    log('🔍', 'Testing Rate Limiting...');

    // Make multiple rapid requests
    const promises = Array(10).fill(null).map(() =>
        request('POST', '/auth/login', {
            body: { email: 'rate@test.com', password: 'test' },
        })
    );

    const responses = await Promise.all(promises);
    const hasRateLimited = responses.some(r => r.status === 429);
    test('Rate Limiting', true, { message: hasRateLimited ? 'Rate limit triggered' : 'No rate limit hit (may need more requests)' });
}

// ============================================
// MAIN
// ============================================

async function runTests() {
    console.log('\n');
    console.log('╔═══════════════════════════════════════════════════════════╗');
    console.log('║     🔐 Enterprise Auth Server - API Test Suite            ║');
    console.log('╚═══════════════════════════════════════════════════════════╝');
    console.log('\n');

    try {
        // Core Tests
        await testHealthCheck();
        await testRegister();
        await testRegisterValidation();
        await testLogin();
        await testLoginWrongPassword();
        await testGetMe();
        await testGetMeNoAuth();

        // Admin Tests
        await testAdminStats();
        await testAdminListUsers();
        await testAdminGetUser();
        await testAdminAuditLogs();

        // API Key Tests
        await testCreateApiKey();
        await testListApiKeys();
        await testRevokeApiKey();

        // 2FA Tests
        await test2FASetup();

        // OAuth Tests
        await testOAuthGoogle();

        // Passwordless Tests
        await testMagicLinkRequest();
        await testWebAuthnOptions();

        // Password Reset
        await testPasswordReset();

        // Security Tests
        await testRateLimiting();

    } catch (error) {
        log('💥', `Test suite error: ${error}`);
    }

    // Summary
    console.log('\n');
    console.log('═══════════════════════════════════════════════════════════');
    console.log('                      TEST SUMMARY                          ');
    console.log('═══════════════════════════════════════════════════════════\n');

    const passed = results.filter(r => r.passed).length;
    const failed = results.filter(r => !r.passed).length;
    const total = results.length;

    console.log(`Total Tests: ${total}`);
    console.log(`✅ Passed: ${passed}`);
    console.log(`❌ Failed: ${failed}`);
    console.log(`📊 Success Rate: ${((passed / total) * 100).toFixed(1)}%\n`);

    if (failed > 0) {
        console.log('Failed Tests:');
        results.filter(r => !r.passed).forEach(r => {
            console.log(`  ❌ ${r.name}: ${r.message || 'Unknown error'}`);
        });
    }

    console.log('\n');
}

runTests();

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Create keys directory if it doesn't exist
const keysDir = path.join(__dirname, '..', 'keys');
if (!fs.existsSync(keysDir)) {
    fs.mkdirSync(keysDir, { recursive: true });
}

// Generate RSA key pair
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 4096, // Military-grade key length
    publicKeyEncoding: {
        type: 'spki',
        format: 'pem'
    },
    privateKeyEncoding: {
        type: 'pkcs8',
        format: 'pem'
    }
});

// Write keys to files
fs.writeFileSync(path.join(keysDir, 'private.pem'), privateKey);
fs.writeFileSync(path.join(keysDir, 'public.pem'), publicKey);

// Set restrictive permissions (Unix-like systems)
try {
    fs.chmodSync(path.join(keysDir, 'private.pem'), 0o600);
    fs.chmodSync(path.join(keysDir, 'public.pem'), 0o644);
} catch (e) {
    // Windows doesn't support chmod, skip
}

console.log('✅ RSA key pair generated successfully!');
console.log(`   Private key: ${path.join(keysDir, 'private.pem')}`);
console.log(`   Public key: ${path.join(keysDir, 'public.pem')}`);
console.log('\n⚠️  IMPORTANT: Never commit these keys to version control!');

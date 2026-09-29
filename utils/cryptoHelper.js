// server/utils/cryptoHelper.js
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';

// -------------------------------------------------------------
// 1. Secret Key Loader with Safe Fallback Check
// -------------------------------------------------------------
// Yeh fallback key exactly frontend se match karni chahiye
const FALLBACK_STATIC_HEX = 'e2b7a9f4c3d1e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3';

function getSecretKey() {
  let rawKey = process.env.CRYPTO_SECRET_KEY || process.env.ENCRYPTION_KEY;
  if (!rawKey || rawKey.trim().length !== 64) {
    rawKey = FALLBACK_STATIC_HEX;
  }
  return Buffer.from(rawKey.trim(), 'hex');
}

// -------------------------------------------------------------
// 2. Text Message Encryption (Strings)
// -------------------------------------------------------------
function encrypt(text) {
  if (text === null || text === undefined) return null;

  const secretKey = getSecretKey();
  
  // Standard 12-byte IV for AES-GCM
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, secretKey, iv);

  let encrypted = cipher.update(String(text), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  return {
    encryptedText: encrypted,
    iv: iv.toString('hex'),
    authTag: authTag
  };
}

// -------------------------------------------------------------
// 3. Text Message Decryption (Strings)
// -------------------------------------------------------------
function decrypt(encryptedText, ivHex, authTagHex) {
  try {
    if (!encryptedText || !ivHex || !authTagHex) return '';

    const secretKey = getSecretKey();

    const decipher = crypto.createDecipheriv(
      ALGORITHM,
      secretKey,
      Buffer.from(ivHex, 'hex')
    );
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

    let decrypted = decipher.update(encryptedText, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch (err) {
    // Error throw ya string return karne ke bajaye empty return karein
    // Taaki frontend ka AdminDashboard apna Master Audit Decryptor chala sake
    return ''; 
  }
}

// -------------------------------------------------------------
// 4. Binary File / Voice Note / Image Encryption (Buffers)
// -------------------------------------------------------------
function encryptBuffer(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new TypeError('Input must be a valid Buffer');
  }

  const secretKey = getSecretKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, secretKey, iv);

  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    encryptedData: encrypted,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex')
  };
}

// -------------------------------------------------------------
// 5. Binary File / Voice Note / Image Decryption (Buffers)
// -------------------------------------------------------------
function decryptBuffer(encryptedBuffer, ivHex, authTagHex) {
  try {
    if (!Buffer.isBuffer(encryptedBuffer)) {
      throw new TypeError('Encrypted input must be a Buffer');
    }

    const secretKey = getSecretKey();
    const decipher = crypto.createDecipheriv(
      ALGORITHM,
      secretKey,
      Buffer.from(ivHex, 'hex')
    );
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

    return Buffer.concat([decipher.update(encryptedBuffer), decipher.final()]);
  } catch (err) {
    throw new Error('Buffer decryption failed: Invalid key, wrong IV, or corrupted payload.');
  }
}

module.exports = {
  encrypt,
  decrypt,
  encryptBuffer,
  decryptBuffer
};
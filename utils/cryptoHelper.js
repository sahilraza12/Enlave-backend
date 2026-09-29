// server/utils/cryptoHelper.js
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';

// -------------------------------------------------------------
// 1. Secret Key Loader with Safe Fallback Check
// -------------------------------------------------------------
function getSecretKey() {
  const rawKey = process.env.CRYPTO_SECRET_KEY || process.env.ENCRYPTION_KEY;
  if (!rawKey || rawKey.length !== 64) {
    console.warn('[CryptoHelper] WARNING: Valid 64-char hex CRYPTO_SECRET_KEY not set in .env. Server-side static crypto will be restricted.');
    return null;
  }
  return Buffer.from(rawKey, 'hex');
}

// -------------------------------------------------------------
// 2. Text Message Encryption (Strings)
// -------------------------------------------------------------
function encrypt(text) {
  if (text === null || text === undefined) return null;

  const secretKey = getSecretKey();
  if (!secretKey) {
    throw new Error('Static encryption key unavailable on server.');
  }

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
    if (!encryptedText || !ivHex || !authTagHex) return encryptedText || '';

    const secretKey = getSecretKey();
    if (!secretKey) return '[Server Key Missing]';

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
    return '[Decryption Failed: Cipher Tampered]';
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
  if (!secretKey) {
    throw new Error('Static encryption key unavailable on server.');
  }

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
    if (!secretKey) {
      throw new Error('Static encryption key unavailable on server.');
    }

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
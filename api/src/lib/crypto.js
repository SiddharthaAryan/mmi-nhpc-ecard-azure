const crypto = require('crypto');

function requireEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return value;
}

function getEncryptionKey() {
  const key = Buffer.from(requireEnv('FIELD_ENCRYPTION_KEY_BASE64'), 'base64');
  if (key.length !== 32) {
    throw new Error('FIELD_ENCRYPTION_KEY_BASE64 must decode to exactly 32 bytes.');
  }
  return key;
}

function encryptText(value) {
  const plain = String(value || '').trim();
  if (!plain) return '';

  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(plain, 'utf8'),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return Buffer.concat([iv, tag, encrypted]).toString('base64');
}

function decryptText(payload) {
  if (!payload) return '';

  const raw = Buffer.from(String(payload), 'base64');
  const iv = raw.subarray(0, 12);
  const tag = raw.subarray(12, 28);
  const encrypted = raw.subarray(28);

  const decipher = crypto.createDecipheriv('aes-256-gcm', getEncryptionKey(), iv);
  decipher.setAuthTag(tag);

  return Buffer.concat([
    decipher.update(encrypted),
    decipher.final()
  ]).toString('utf8');
}

function keyedHash(value) {
  const secret = requireEnv('HASH_SECRET');
  return crypto
    .createHmac('sha256', secret)
    .update(String(value || '').trim())
    .digest('hex');
}

function maskPhone(phone) {
  const clean = String(phone || '').replace(/\D/g, '');
  if (clean.length !== 10) return '';
  return `${clean.slice(0, 2)}XXXXXX${clean.slice(-2)}`;
}

module.exports = {
  encryptText,
  decryptText,
  keyedHash,
  maskPhone
};

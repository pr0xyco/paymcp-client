import crypto from 'crypto';

export const DEFAULT_ENCRYPTION_KEY_ENV_VAR = 'TURTLE_SECRET_KEY';
const ENCRYPTION_ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;

export function encrypt(text: string, encryptionKey: string): string {
  // Convert base64 key to Buffer
  const key = Buffer.from(encryptionKey, 'base64');
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ENCRYPTION_ALGORITHM, key, iv);
  
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  
  const authTag = cipher.getAuthTag();
  
  // Combine IV, encrypted data, and auth tag
  return iv.toString('hex') + ':' + encrypted + ':' + authTag.toString('hex');
}

export function decrypt(encryptedText: string, encryptionKey: string): string {
  // Convert base64 key to Buffer
  const key = Buffer.from(encryptionKey, 'base64');
  const parts = encryptedText.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted text format');
  }
  
  const [ivHex, encrypted, authTagHex] = parts;
  
  try {
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    
    const decipher = crypto.createDecipheriv(ENCRYPTION_ALGORITHM, key, iv);
    decipher.setAuthTag(authTag);
    
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    
    return decrypted;
  } catch (error) {
    throw new Error('Failed to decrypt: Invalid or corrupted data');
  }
}

export function hashApiKey(apiKey: string, pepper: string): string {
  // Combine API key with pepper before hashing
  return crypto.createHash('sha256')
    .update(apiKey + pepper)
    .digest('hex');
}
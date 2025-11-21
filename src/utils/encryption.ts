/**
 * Encryption & Data Protection Utilities
 */

import crypto from 'crypto';
import { configManager } from '../config';

export class EncryptionService {
  private algorithm = 'aes-256-gcm';
  private key: Buffer;

  constructor() {
    const encryptionKey = configManager.getConfig().encryptionKey;
    // Hash the key to ensure it's exactly 32 bytes
    this.key = crypto
      .createHash('sha256')
      .update(encryptionKey)
      .digest();
  }

  /**
   * Encrypt sensitive data
   */
  public encrypt(data: string): { encrypted: string; iv: string; authTag: string } {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(this.algorithm, this.key, iv) as crypto.CipherGCM;

    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    const authTag = cipher.getAuthTag();

    return {
      encrypted,
      iv: iv.toString('hex'),
      authTag: authTag.toString('hex'),
    };
  }

  /**
   * Decrypt sensitive data
   */
  public decrypt(encrypted: string, iv: string, authTag: string): string {
    const decipher = crypto.createDecipheriv(
      this.algorithm,
      this.key,
      Buffer.from(iv, 'hex')
    ) as crypto.DecipherGCM;

    decipher.setAuthTag(Buffer.from(authTag, 'hex'));

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }

  /**
   * Hash sensitive data (one-way)
   */
  public hash(data: string): string {
    return crypto
      .createHash('sha256')
      .update(data)
      .digest('hex');
  }

  /**
   * Verify hashed data
   */
  public verifyHash(data: string, hash: string): boolean {
    return this.hash(data) === hash;
  }

  /**
   * Generate a cryptographic salt
   */
  public generateSalt(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Hash with salt
   */
  public hashWithSalt(data: string, salt: string): string {
    return crypto
      .createHmac('sha256', salt)
      .update(data)
      .digest('hex');
  }

  /**
   * Generate random token
   */
  public generateToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }
}

export const encryptionService = new EncryptionService();

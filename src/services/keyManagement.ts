import crypto from 'crypto';
import { configManager } from '../config';
import { logger } from '../utils/logger';

interface EnvelopeEncryptionResult {
  ciphertext: string;
  iv: string;
  authTag: string;
  encryptedKey: string;
  keyVersion: string;
}

export class KeyManagementService {
  private jwks: { kid: string; key: string }[] = [];
  private revokedTokens: Map<string, number> = new Map();

  constructor() {
    this.rotateJwks();
  }

  public rotateJwks(): void {
    const kid = crypto.randomUUID();
    const key = crypto.randomBytes(32).toString('hex');
    this.jwks.unshift({ kid, key });
    this.trimKeys();
    logger.info('JWKS rotated', { kid });
  }

  public getCurrentJwks() {
    return this.jwks;
  }

  public revokeToken(jti: string): void {
    const ttlMinutes = configManager.getConfig().tokenRevocationTtlMinutes;
    this.revokedTokens.set(jti, Date.now() + ttlMinutes * 60 * 1000);
  }

  public isRevoked(jti: string): boolean {
    const expiry = this.revokedTokens.get(jti);
    if (!expiry) return false;
    if (expiry < Date.now()) {
      this.revokedTokens.delete(jti);
      return false;
    }
    return true;
  }

  public envelopeEncrypt(plaintext: Buffer): EnvelopeEncryptionResult {
    const keyVersion = configManager.getConfig().kmsKeyId || 'local-default';
    const dataKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', dataKey, iv);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const authTag = cipher.getAuthTag();

    const encryptedKey = this.wrapKey(dataKey, keyVersion);

    return {
      ciphertext: ciphertext.toString('base64'),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
      encryptedKey: encryptedKey.toString('base64'),
      keyVersion,
    };
  }

  public envelopeDecrypt(payload: EnvelopeEncryptionResult): Buffer {
    const dataKey = this.unwrapKey(Buffer.from(payload.encryptedKey, 'base64'), payload.keyVersion);
    const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, Buffer.from(payload.iv, 'base64'));
    decipher.setAuthTag(Buffer.from(payload.authTag, 'base64'));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(payload.ciphertext, 'base64')),
      decipher.final(),
    ]);
    return plaintext;
  }

  private wrapKey(key: Buffer, keyVersion: string): Buffer {
    const kmsKey = crypto.createHash('sha256').update(keyVersion).digest();
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', kmsKey, iv.subarray(0, 12));
    const ciphertext = Buffer.concat([cipher.update(key), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), ciphertext]);
  }

  private unwrapKey(wrappedKey: Buffer, keyVersion: string): Buffer {
    const kmsKey = crypto.createHash('sha256').update(keyVersion).digest();
    const iv = wrappedKey.subarray(0, 12);
    const authTag = wrappedKey.subarray(12, 28);
    const ciphertext = wrappedKey.subarray(28);
    const decipher = crypto.createDecipheriv('aes-256-gcm', kmsKey, iv);
    decipher.setAuthTag(authTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  }

  private trimKeys() {
    const maxKeys = 5;
    if (this.jwks.length > maxKeys) {
      this.jwks = this.jwks.slice(0, maxKeys);
    }
  }
}

export const keyManagementService = new KeyManagementService();

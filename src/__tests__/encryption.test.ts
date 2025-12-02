/**
 * Encryption Service Tests
 */

import { describe, it, expect } from 'vitest';
import { encryptionService } from '../utils/encryption';

describe('EncryptionService', () => {
  const sensitiveData = 'This is sensitive information';

  describe('Encryption and Decryption', () => {
    it('should encrypt data', () => {
      const result = encryptionService.encrypt(sensitiveData);

      expect(result).toBeDefined();
      expect(result.encrypted).toBeDefined();
      expect(result.iv).toBeDefined();
      expect(result.authTag).toBeDefined();
      expect(result.encrypted).not.toBe(sensitiveData);
    });

    it('should decrypt encrypted data', () => {
      const encrypted = encryptionService.encrypt(sensitiveData);
      const decrypted = encryptionService.decrypt(
        encrypted.encrypted,
        encrypted.iv,
        encrypted.authTag
      );

      expect(decrypted).toBe(sensitiveData);
    });

    it('should fail to decrypt with wrong auth tag', () => {
      const encrypted = encryptionService.encrypt(sensitiveData);

      expect(() => {
        encryptionService.decrypt(
          encrypted.encrypted,
          encrypted.iv,
          'wrong-auth-tag-00000000000000000000000000000000'
        );
      }).toThrow();
    });

    it('should generate different encrypted outputs for same input', () => {
      const encrypted1 = encryptionService.encrypt(sensitiveData);
      const encrypted2 = encryptionService.encrypt(sensitiveData);

      // Should be different due to random IV
      expect(encrypted1.encrypted).not.toBe(encrypted2.encrypted);
      expect(encrypted1.iv).not.toBe(encrypted2.iv);
    });
  });

  describe('Hashing', () => {
    it('should hash data', () => {
      const hash = encryptionService.hash(sensitiveData);

      expect(hash).toBeDefined();
      expect(typeof hash).toBe('string');
      expect(hash).not.toBe(sensitiveData);
      expect(hash.length).toBe(64); // SHA256 hex length
    });

    it('should produce consistent hash', () => {
      const hash1 = encryptionService.hash(sensitiveData);
      const hash2 = encryptionService.hash(sensitiveData);

      expect(hash1).toBe(hash2);
    });

    it('should verify hash', () => {
      const hash = encryptionService.hash(sensitiveData);
      const verified = encryptionService.verifyHash(sensitiveData, hash);

      expect(verified).toBe(true);
    });

    it('should fail hash verification with wrong data', () => {
      const hash = encryptionService.hash(sensitiveData);
      const verified = encryptionService.verifyHash('different data', hash);

      expect(verified).toBe(false);
    });
  });

  describe('Salt Generation', () => {
    it('should generate salt', () => {
      const salt = encryptionService.generateSalt();

      expect(salt).toBeDefined();
      expect(salt.length).toBeGreaterThan(0);
    });

    it('should generate different salts', () => {
      const salt1 = encryptionService.generateSalt();
      const salt2 = encryptionService.generateSalt();

      expect(salt1).not.toBe(salt2);
    });

    it('should generate custom length salt', () => {
      const salt = encryptionService.generateSalt(16);
      expect(salt.length).toBe(32); // 16 bytes = 32 hex chars
    });
  });

  describe('HMAC Hashing', () => {
    it('should hash with salt', () => {
      const salt = encryptionService.generateSalt();
      const hash = encryptionService.hashWithSalt(sensitiveData, salt);

      expect(hash).toBeDefined();
      expect(hash).not.toBe(sensitiveData);
    });

    it('should produce different hash with different salt', () => {
      const salt1 = encryptionService.generateSalt();
      const salt2 = encryptionService.generateSalt();

      const hash1 = encryptionService.hashWithSalt(sensitiveData, salt1);
      const hash2 = encryptionService.hashWithSalt(sensitiveData, salt2);

      expect(hash1).not.toBe(hash2);
    });
  });

  describe('Token Generation', () => {
    it('should generate random token', () => {
      const token = encryptionService.generateToken();

      expect(token).toBeDefined();
      expect(typeof token).toBe('string');
      expect(token.length).toBeGreaterThan(0);
    });

    it('should generate different tokens', () => {
      const token1 = encryptionService.generateToken();
      const token2 = encryptionService.generateToken();

      expect(token1).not.toBe(token2);
    });

    it('should generate custom length token', () => {
      const token = encryptionService.generateToken(64);
      expect(token.length).toBe(128); // 64 bytes = 128 hex chars
    });
  });
});

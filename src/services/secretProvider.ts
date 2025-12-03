import { configManager } from '../config';
import { logger } from '../utils/logger';

export class SecretProviderService {
  private cache: Map<string, string> = new Map();

  public async getSecret(key: string): Promise<string | undefined> {
    if (this.cache.has(key)) {
      return this.cache.get(key);
    }

    const provider = configManager.getConfig().secretManager;
    const namespacedKey = `${configManager.getConfig().secretsNamespace}/${key}`;
    // Simulated providers; real implementations would call SDKs.
    const secret = process.env[key] || process.env[namespacedKey.replace(/\//g, '_').toUpperCase()];
    if (secret) {
      this.cache.set(key, secret);
      return secret;
    }

    logger.warn('Secret not found in provider, falling back to undefined', { provider, key });
    return undefined;
  }

  public async rotateSecret(key: string, value: string): Promise<void> {
    this.cache.set(key, value);
    logger.info('Secret rotated', { key, provider: configManager.getConfig().secretManager });
  }
}

export const secretProviderService = new SecretProviderService();

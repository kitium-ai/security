/**
 * HTTPS/TLS Configuration
 * Provides utilities for setting up secure HTTPS servers
 */

import https from 'https';
import http from 'http';
import fs from 'fs';
import path from 'path';
import { Express } from 'express';
import { logger } from '../utils/logger';

export interface TLSConfig {
  keyPath: string;
  certPath: string;
  caPath?: string;
  port?: number;
  redirectHttpToHttps?: boolean;
  httpPort?: number;
  minVersion?: string;
  ciphers?: string;
  honorCipherOrder?: boolean;
}

export interface HTTPSServerOptions {
  key: Buffer;
  cert: Buffer;
  ca?: Buffer;
  minVersion?: 'TLSv1' | 'TLSv1.1' | 'TLSv1.2' | 'TLSv1.3';
  ciphers?: string;
  honorCipherOrder?: boolean;
  requestCert?: boolean;
  rejectUnauthorized?: boolean;
}

/**
 * TLS Configuration Service
 */
export class TLSConfigurationService {
  /**
   * Secure TLS/SSL configuration following OWASP recommendations
   */
  private static readonly DEFAULT_MIN_VERSION = 'TLSv1.2';

  /**
   * Strong cipher suites (TLS 1.2+) - following Mozilla Modern configuration
   */
  private static readonly DEFAULT_CIPHERS = [
    'TLS_AES_128_GCM_SHA256',
    'TLS_AES_256_GCM_SHA384',
    'TLS_CHACHA20_POLY1305_SHA256',
    'ECDHE-ECDSA-AES128-GCM-SHA256',
    'ECDHE-RSA-AES128-GCM-SHA256',
    'ECDHE-ECDSA-AES256-GCM-SHA384',
    'ECDHE-RSA-AES256-GCM-SHA384',
  ].join(':');

  /**
   * Load TLS certificates from file system
   */
  private loadCertificates(config: TLSConfig): HTTPSServerOptions {
    try {
      const key = fs.readFileSync(path.resolve(config.keyPath));
      const cert = fs.readFileSync(path.resolve(config.certPath));
      let ca: Buffer | undefined;

      if (config.caPath) {
        ca = fs.readFileSync(path.resolve(config.caPath));
      }

      logger.info('TLS certificates loaded successfully', {
        keyPath: config.keyPath,
        certPath: config.certPath,
      });

      return {
        key,
        cert,
        ca,
        minVersion: (config.minVersion || TLSConfigurationService.DEFAULT_MIN_VERSION) as 'TLSv1.2' | 'TLSv1.3',
        ciphers: config.ciphers || TLSConfigurationService.DEFAULT_CIPHERS,
        honorCipherOrder: config.honorCipherOrder !== false,
        requestCert: false,
        rejectUnauthorized: true,
      };
    } catch (error) {
      logger.error('Failed to load TLS certificates', {
        error: (error as Error).message,
      });
      throw new Error(`TLS certificate loading failed: ${(error as Error).message}`);
    }
  }

  /**
   * Create HTTPS server with TLS configuration
   */
  public createHTTPSServer(app: Express, config: TLSConfig): https.Server {
    const httpsOptions = this.loadCertificates(config);

    const server = https.createServer(httpsOptions, app);

    const port = config.port || 443;

    server.listen(port, () => {
      logger.info('HTTPS server started', {
        port,
        minVersion: httpsOptions.minVersion,
        tlsEnabled: true,
      });
    });

    server.on('error', (error: NodeJS.ErrnoException) => {
      logger.error('HTTPS server error', {
        error: error.message,
        code: error.code,
      });
      throw error;
    });

    return server;
  }

  /**
   * Create HTTP to HTTPS redirect server
   */
  public createHTTPRedirectServer(httpsPort: number = 443, httpPort: number = 80): http.Server {
    const server = http.createServer((req, res) => {
      const host = req.headers.host?.split(':')[0] || 'localhost';
      const redirectUrl = `https://${host}${httpsPort !== 443 ? `:${httpsPort}` : ''}${req.url}`;

      logger.debug('HTTP to HTTPS redirect', {
        from: `http://${req.headers.host}${req.url}`,
        to: redirectUrl,
      });

      res.writeHead(301, {
        'Location': redirectUrl,
        'Content-Type': 'text/plain',
      });
      res.end('Redirecting to HTTPS');
    });

    server.listen(httpPort, () => {
      logger.info('HTTP redirect server started', {
        httpPort,
        redirectingTo: httpsPort,
      });
    });

    server.on('error', (error: NodeJS.ErrnoException) => {
      logger.error('HTTP redirect server error', {
        error: error.message,
        code: error.code,
      });
      throw error;
    });

    return server;
  }

  /**
   * Setup complete HTTPS server with HTTP redirect
   */
  public setupSecureServer(app: Express, config: TLSConfig): {
    httpsServer: https.Server;
    httpServer?: http.Server;
  } {
    const httpsServer = this.createHTTPSServer(app, config);

    let httpServer: http.Server | undefined;

    if (config.redirectHttpToHttps) {
      const httpsPort = config.port || 443;
      const httpPort = config.httpPort || 80;
      httpServer = this.createHTTPRedirectServer(httpsPort, httpPort);
    }

    return { httpsServer, httpServer };
  }

  /**
   * Generate self-signed certificate for development (NOT FOR PRODUCTION)
   */
  public generateSelfSignedCert(): { key: string; cert: string } {
    logger.warn('Self-signed certificate generation requested - USE ONLY FOR DEVELOPMENT');

    // This is a simplified version - in practice, you would use openssl or node-forge
    const instructions = `
To generate a self-signed certificate for development, run:

openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=localhost"

For production, use certificates from a trusted Certificate Authority (Let's Encrypt, etc.)
    `;

    logger.info(instructions);

    return {
      key: './key.pem',
      cert: './cert.pem',
    };
  }

  /**
   * Validate TLS configuration
   */
  public validateTLSConfig(config: TLSConfig): { valid: boolean; errors: string[] } {
    const errors: string[] = [];

    if (!config.keyPath) {
      errors.push('TLS key path is required');
    }

    if (!config.certPath) {
      errors.push('TLS certificate path is required');
    }

    if (config.keyPath && !fs.existsSync(path.resolve(config.keyPath))) {
      errors.push(`TLS key file not found: ${config.keyPath}`);
    }

    if (config.certPath && !fs.existsSync(path.resolve(config.certPath))) {
      errors.push(`TLS certificate file not found: ${config.certPath}`);
    }

    if (config.caPath && !fs.existsSync(path.resolve(config.caPath))) {
      errors.push(`CA certificate file not found: ${config.caPath}`);
    }

    const validMinVersions = ['TLSv1.2', 'TLSv1.3'];
    if (config.minVersion && !validMinVersions.includes(config.minVersion)) {
      errors.push(`Invalid TLS version: ${config.minVersion}. Use TLSv1.2 or TLSv1.3`);
    }

    return {
      valid: errors.length === 0,
      errors,
    };
  }
}

export const tlsConfigurationService = new TLSConfigurationService();

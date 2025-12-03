import fs from 'fs';
import path from 'path';
import { configManager } from '../config';
import { keyManagementService } from '../services/keyManagement';

export function generateConfigTemplate(destination = '.env.example') {
  const template = `NODE_ENV=production\nJWT_SECRET=change-me-32-chars\nENCRYPTION_KEY=change-me-32-chars\nRESPONSE_SIGNING_KEY=rotate-me\nKMS_KEY_ID=alias/security\n`;
  fs.writeFileSync(path.resolve(destination), template);
  return destination;
}

export function rotateKeys(): { jwksKid: string } {
  keyManagementService.rotateJwks();
  const [current] = keyManagementService.getCurrentJwks();
  return { jwksKid: current?.kid };
}

export function validateEnvironment(): { valid: boolean; errors: string[] } {
  return configManager.validateConfig();
}

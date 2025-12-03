import { DataClassification } from '../types';
import { configManager } from '../config';

export class DataGovernanceService {
  public classify(data: Record<string, any>): DataClassification[] {
    const piiFields = configManager.getConfig().piiFields || [];
    return Object.keys(data).map((field) => ({
      field,
      tags: piiFields.includes(field) ? ['pii'] : ['general'],
      maskedValue: this.maskValue(data[field]),
    }));
  }

  public maskValue(value: any): string {
    if (typeof value === 'string') {
      return value.length > 6
        ? `${value.substring(0, 3)}***${value.substring(value.length - 2)}`
        : '***';
    }
    return '***';
  }

  public enforceRetention(timestamp: number): boolean {
    const retentionDays = configManager.getConfig().auditRetentionDays || 30;
    const expiry = timestamp + retentionDays * 24 * 60 * 60 * 1000;
    return Date.now() <= expiry;
  }
}

export const dataGovernanceService = new DataGovernanceService();

/**
 * Logging Utility
 */

import winston from 'winston';
import { configManager } from '../config';

const levels = {
  error: 0,
  warn: 1,
  info: 2,
  debug: 3,
};

const colors = {
  error: 'red',
  warn: 'yellow',
  info: 'green',
  debug: 'blue',
};

winston.addColors(colors);

const format = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    const metaStr = Object.keys(meta).length ? JSON.stringify(meta) : '';
    return `${timestamp} [${level.toUpperCase()}]: ${message} ${metaStr}`;
  })
);

const consoleTransport = new winston.transports.Console({
  format: winston.format.combine(
    winston.format.colorize(),
    format
  ),
});

const fileTransport = new winston.transports.File({
  filename: 'logs/error.log',
  level: 'error',
  format,
});

const combinedFileTransport = new winston.transports.File({
  filename: 'logs/combined.log',
  format,
});

const config = configManager.getConfig();

export const logger = winston.createLogger({
  level: config.logLevel,
  levels,
  transports: [
    consoleTransport,
    fileTransport,
    combinedFileTransport,
  ],
});

export default logger;

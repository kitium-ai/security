/**
 * SQL Injection Prevention Utilities
 * Provides utilities and examples for preventing SQL injection attacks
 *
 * IMPORTANT: Always use parameterized queries/prepared statements with your database library
 */

import { logger } from '../utils/logger';
import { inputSanitizer } from '../utils/sanitize';

/**
 * SQL Query Builder with Parameterization
 * This is a simplified example - in production, use established ORMs like:
 * - Sequelize
 * - TypeORM
 * - Prisma
 * - Knex.js
 */
export class SafeQueryBuilder {
  private params: any[] = [];
  private query: string = '';

  /**
   * SELECT query with parameterization
   */
  public select(table: string, columns: string[] = ['*']): this {
    const sanitizedTable = inputSanitizer.sanitizeSQLIdentifier(table);
    const sanitizedColumns = columns.map(col => inputSanitizer.sanitizeSQLIdentifier(col));

    if (!sanitizedTable) {
      throw new Error('Invalid table name');
    }

    this.query = `SELECT ${sanitizedColumns.join(', ')} FROM ${sanitizedTable}`;
    return this;
  }

  /**
   * WHERE clause with parameterized values
   */
  public where(column: string, operator: string, value: any): this {
    const sanitizedColumn = inputSanitizer.sanitizeSQLIdentifier(column);

    if (!sanitizedColumn) {
      throw new Error('Invalid column name');
    }

    const allowedOperators = ['=', '!=', '>', '<', '>=', '<=', 'LIKE', 'IN'];
    if (!allowedOperators.includes(operator.toUpperCase())) {
      throw new Error('Invalid operator');
    }

    this.params.push(value);
    const paramIndex = this.params.length;

    if (this.query.includes('WHERE')) {
      this.query += ` AND ${sanitizedColumn} ${operator} $${paramIndex}`;
    } else {
      this.query += ` WHERE ${sanitizedColumn} ${operator} $${paramIndex}`;
    }

    return this;
  }

  /**
   * ORDER BY clause
   */
  public orderBy(column: string, direction: 'ASC' | 'DESC' = 'ASC'): this {
    const sanitizedColumn = inputSanitizer.sanitizeSQLIdentifier(column);

    if (!sanitizedColumn) {
      throw new Error('Invalid column name');
    }

    const dir = direction.toUpperCase() === 'DESC' ? 'DESC' : 'ASC';
    this.query += ` ORDER BY ${sanitizedColumn} ${dir}`;

    return this;
  }

  /**
   * LIMIT clause
   */
  public limit(count: number): this {
    const sanitizedCount = inputSanitizer.sanitizeInteger(count);

    if (sanitizedCount === null || sanitizedCount < 0) {
      throw new Error('Invalid limit value');
    }

    this.query += ` LIMIT ${sanitizedCount}`;
    return this;
  }

  /**
   * Get the query and parameters
   */
  public build(): { query: string; params: any[] } {
    return {
      query: this.query,
      params: this.params,
    };
  }

  /**
   * Reset the builder
   */
  public reset(): void {
    this.query = '';
    this.params = [];
  }
}

/**
 * Examples of SQL Injection Prevention
 */
export class SQLInjectionExamples {
  /**
   * BAD: Vulnerable to SQL injection (DO NOT USE)
   */
  public static vulnerableQuery(userId: string): string {
    // ❌ NEVER DO THIS - String concatenation is vulnerable
    return `SELECT * FROM users WHERE id = '${userId}'`;
    // Attack example: userId = "1' OR '1'='1"
    // Results in: SELECT * FROM users WHERE id = '1' OR '1'='1'
  }

  /**
   * GOOD: Safe parameterized query (PostgreSQL syntax)
   */
  public static safeParameterizedQuery(userId: string): { query: string; params: any[] } {
    // ✅ Use parameterized queries
    return {
      query: 'SELECT * FROM users WHERE id = $1',
      params: [userId],
    };
  }

  /**
   * GOOD: Safe query with multiple parameters
   */
  public static safeQueryWithMultipleParams(email: string, status: string): { query: string; params: any[] } {
    return {
      query: 'SELECT * FROM users WHERE email = $1 AND status = $2',
      params: [email, status],
    };
  }

  /**
   * GOOD: Safe INSERT with parameterized values
   */
  public static safeInsert(username: string, email: string, hashedPassword: string): { query: string; params: any[] } {
    return {
      query: 'INSERT INTO users (username, email, password) VALUES ($1, $2, $3) RETURNING id',
      params: [username, email, hashedPassword],
    };
  }

  /**
   * GOOD: Safe UPDATE with parameterized values
   */
  public static safeUpdate(userId: string, newEmail: string): { query: string; params: any[] } {
    return {
      query: 'UPDATE users SET email = $1, updated_at = NOW() WHERE id = $2',
      params: [newEmail, userId],
    };
  }

  /**
   * GOOD: Safe DELETE with parameterized values
   */
  public static safeDelete(userId: string): { query: string; params: any[] } {
    return {
      query: 'DELETE FROM users WHERE id = $1',
      params: [userId],
    };
  }

  /**
   * GOOD: Safe dynamic WHERE IN clause
   */
  public static safeDynamicWhereIn(userIds: string[]): { query: string; params: any[] } {
    // Create placeholders for each value
    const placeholders = userIds.map((_, index) => `$${index + 1}`).join(', ');

    return {
      query: `SELECT * FROM users WHERE id IN (${placeholders})`,
      params: userIds,
    };
  }

  /**
   * Example: Using Sequelize ORM (safe by default)
   */
  public static sequelizeExample() {
    return `
// Sequelize automatically uses parameterized queries
import { Sequelize, Model, DataTypes } from 'sequelize';

const sequelize = new Sequelize('database', 'username', 'password', {
  dialect: 'postgres',
  logging: false,
});

// Safe query
const user = await User.findOne({
  where: {
    email: userInput, // Automatically parameterized
  },
});

// Safe raw query with parameters
const [results] = await sequelize.query(
  'SELECT * FROM users WHERE email = :email',
  {
    replacements: { email: userInput },
    type: QueryTypes.SELECT,
  }
);
`;
  }

  /**
   * Example: Using TypeORM (safe by default)
   */
  public static typeORMExample() {
    return `
// TypeORM automatically uses parameterized queries
import { getRepository } from 'typeorm';

const userRepository = getRepository(User);

// Safe query
const user = await userRepository.findOne({
  where: {
    email: userInput, // Automatically parameterized
  },
});

// Safe query builder
const users = await userRepository
  .createQueryBuilder('user')
  .where('user.email = :email', { email: userInput }) // Parameterized
  .andWhere('user.status = :status', { status: 'active' })
  .getMany();
`;
  }

  /**
   * Example: Using Prisma (safe by default)
   */
  public static prismaExample() {
    return `
// Prisma automatically uses parameterized queries
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

// Safe query
const user = await prisma.user.findUnique({
  where: {
    email: userInput, // Automatically parameterized
  },
});

// Safe raw query with parameters
const users = await prisma.$queryRaw\`
  SELECT * FROM users WHERE email = \${userInput}
\`; // Template literal automatically parameterized
`;
  }

  /**
   * Example: Using Knex.js query builder (safe by default)
   */
  public static knexExample() {
    return `
// Knex.js automatically uses parameterized queries
import knex from 'knex';

const db = knex({
  client: 'pg',
  connection: process.env.DATABASE_URL,
});

// Safe query
const users = await db('users')
  .where('email', userInput) // Automatically parameterized
  .select('*');

// Safe raw query with parameters
const results = await db.raw(
  'SELECT * FROM users WHERE email = ?',
  [userInput]
);
`;
  }
}

/**
 * Validation helpers for database operations
 */
export class DatabaseValidation {
  /**
   * Validate table name
   */
  public static validateTableName(tableName: string): boolean {
    // Only allow alphanumeric and underscore
    const pattern = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
    const isValid = pattern.test(tableName);

    if (!isValid) {
      logger.warn('Invalid table name detected', { tableName });
    }

    return isValid;
  }

  /**
   * Validate column name
   */
  public static validateColumnName(columnName: string): boolean {
    // Only allow alphanumeric and underscore
    const pattern = /^[a-zA-Z_][a-zA-Z0-9_]*$/;
    const isValid = pattern.test(columnName);

    if (!isValid) {
      logger.warn('Invalid column name detected', { columnName });
    }

    return isValid;
  }

  /**
   * Validate ORDER BY direction
   */
  public static validateOrderDirection(direction: string): boolean {
    const validDirections = ['ASC', 'DESC'];
    const isValid = validDirections.includes(direction.toUpperCase());

    if (!isValid) {
      logger.warn('Invalid ORDER BY direction', { direction });
    }

    return isValid;
  }

  /**
   * Validate LIMIT value
   */
  public static validateLimit(limit: any): number | null {
    const num = inputSanitizer.sanitizeInteger(limit);

    if (num === null || num < 0 || num > 10000) {
      logger.warn('Invalid LIMIT value', { limit });
      return null;
    }

    return num;
  }

  /**
   * Validate OFFSET value
   */
  public static validateOffset(offset: any): number | null {
    const num = inputSanitizer.sanitizeInteger(offset);

    if (num === null || num < 0) {
      logger.warn('Invalid OFFSET value', { offset });
      return null;
    }

    return num;
  }
}

export const safeQueryBuilder = new SafeQueryBuilder();
export const sqlInjectionExamples = SQLInjectionExamples;
export const databaseValidation = DatabaseValidation;

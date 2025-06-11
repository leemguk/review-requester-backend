// src/lib/prisma.ts - Optimized for Neon with connection pooling
import { Pool, PoolClient } from 'pg'

// Use connection pooling for better performance
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10, // max number of connections
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
  // Neon-specific optimizations
  ssl: {
    rejectUnauthorized: false
  }
});

// Log pool errors
pool.on('error', (err) => {
  console.error('Unexpected pool error:', err);
});

export const db = {
  async query(text: string, params?: any[]) {
    const start = Date.now();
    try {
      const result = await pool.query(text, params);
      const duration = Date.now() - start;

      // Log slow queries for debugging
      if (duration > 1000) {
        console.log('Slow query:', { 
          query: text.substring(0, 50) + '...', 
          duration: duration + 'ms' 
        });
      }

      return result;
    } catch (error) {
      console.error('Database query error:', error);
      throw error;
    }
  },

  async getClient(): Promise<PoolClient> {
    return await pool.connect();
  },

  async end() {
    await pool.end();
  }
}

// Test connection with timing
export async function testConnection() {
  try {
    const start = Date.now();
    const result = await db.query('SELECT NOW() as current_time');
    const duration = Date.now() - start;
    console.log(`✅ Database connected successfully in ${duration}ms:`, result.rows[0]);
    return true;
  } catch (error) {
    console.error('❌ Database connection failed:', error);
    return false;
  }
}

// Run connection test on startup
testConnection();

export const prisma = db;
export default db;
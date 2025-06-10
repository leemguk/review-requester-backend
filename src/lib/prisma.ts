// src/lib/prisma.ts - Now using direct PostgreSQL connection
import { Pool, PoolClient } from 'pg'

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
})

export const db = {
  async query(text: string, params?: any[]) {
    const client = await pool.connect()
    try {
      const result = await client.query(text, params)
      return result
    } finally {
      client.release()
    }
  },

  async getClient(): Promise<PoolClient> {
    return await pool.connect()
  },

  async end() {
    await pool.end()
  }
}

// Test connection
export async function testConnection() {
  try {
    const result = await db.query('SELECT NOW() as current_time')
    console.log('✅ Database connected successfully:', result.rows[0])
    return true
  } catch (error) {
    console.error('❌ Database connection failed:', error)
    return false
  }
}

// For backward compatibility, export as prisma
export const prisma = db

export default db
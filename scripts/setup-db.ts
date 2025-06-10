import { db, testConnection } from '../src/lib/prisma'

const createTables = async () => {
  try {
    console.log('🔄 Setting up database tables...')

    // Test connection first
    const isConnected = await testConnection()
    if (!isConnected) {
      throw new Error('Could not connect to database')
    }

    // Enable UUID extension
    await db.query('CREATE EXTENSION IF NOT EXISTS "uuid-ossp"')
    console.log('✅ UUID extension enabled')

    // Create users table
    await db.query(`
      CREATE TABLE IF NOT EXISTS users (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          email VARCHAR(255) UNIQUE NOT NULL,
          name VARCHAR(255),
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `)
    console.log('✅ Users table created')

    // Create campaigns table
    await db.query(`
      CREATE TABLE IF NOT EXISTS campaigns (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          name VARCHAR(255) NOT NULL,
          description TEXT,
          status VARCHAR(50) DEFAULT 'draft',
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `)
    console.log('✅ Campaigns table created')

    // Create emails table
    await db.query(`
      CREATE TABLE IF NOT EXISTS emails (
          id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
          to_email VARCHAR(255) NOT NULL,
          subject VARCHAR(500) NOT NULL,
          content TEXT NOT NULL,
          status VARCHAR(50) DEFAULT 'pending',
          sent_at TIMESTAMP WITH TIME ZONE,
          user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          campaign_id UUID REFERENCES campaigns(id) ON DELETE SET NULL,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
          updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `)
    console.log('✅ Emails table created')

    // Create indexes
    await db.query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    await db.query('CREATE INDEX IF NOT EXISTS idx_campaigns_user_id ON campaigns(user_id)')
    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_user_id ON emails(user_id)')
    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_campaign_id ON emails(campaign_id)')
    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status)')
    console.log('✅ Indexes created')

    console.log('🎉 Database setup complete!')

  } catch (error) {
    console.error('❌ Database setup failed:', error)
    process.exit(1)
  } finally {
    await db.end()
  }
}

createTables()
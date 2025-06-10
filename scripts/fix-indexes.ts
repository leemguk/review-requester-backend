import { db } from '../src/lib/prisma'

const createIndexes = async () => {
  try {
    console.log('🔄 Creating database indexes with correct column names...')

    // Create indexes using the actual column names (camelCase from Prisma)
    await db.query('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
    console.log('✅ Users email index created')

    // Note: using "userId" (camelCase) not "user_id" (snake_case)
    await db.query('CREATE INDEX IF NOT EXISTS idx_campaigns_userId ON campaigns("userId")')
    console.log('✅ Campaigns userId index created')

    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_userId ON emails("userId")')
    console.log('✅ Emails userId index created')

    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_campaignId ON emails("campaignId")')
    console.log('✅ Emails campaignId index created')

    await db.query('CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status)')
    console.log('✅ Emails status index created')

    console.log('🎉 All indexes created successfully!')

  } catch (error) {
    console.error('❌ Index creation failed:', error)
  } finally {
    await db.end()
  }
}

createIndexes()
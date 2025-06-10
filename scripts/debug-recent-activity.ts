// scripts/debug-recent-activity.ts
import { db } from '../src/lib/prisma'

const debugRecentActivity = async () => {
  try {
    console.log('🔍 Debugging Recent Activity...')

    // Check all emails in database
    const allEmails = await db.query(`
      SELECT 
        id, 
        "to", 
        subject, 
        content, 
        status, 
        "userId", 
        "createdAt"
      FROM emails 
      ORDER BY "createdAt" DESC 
      LIMIT 10
    `)

    console.log(`📧 Found ${allEmails.rows.length} emails total:`)
    allEmails.rows.forEach((email, index) => {
      console.log(`${index + 1}. To: ${email.to}`)
      console.log(`   Subject: "${email.subject}"`)
      console.log(`   Content: "${email.content}"`)
      console.log(`   Status: "${email.status}"`)
      console.log(`   UserId: "${email.userId}" (type: ${typeof email.userId})`)
      console.log(`   Created: ${email.createdAt}`)
      console.log('   ---')
    })

    // Check what user ID the analytics is looking for
    console.log('\n🔍 Testing analytics query with different user IDs...')

    // Test with string '1'
    const stringResult = await db.query(`
      SELECT COUNT(*) as count
      FROM emails 
      WHERE "userId" = $1
    `, ['1'])
    console.log(`String '1': ${stringResult.rows[0].count} emails`)

    // Test with number 1
    const numberResult = await db.query(`
      SELECT COUNT(*) as count
      FROM emails 
      WHERE "userId" = $1
    `, [1])
    console.log(`Number 1: ${numberResult.rows[0].count} emails`)

    // Check users table
    const users = await db.query(`SELECT id, email FROM users LIMIT 5`)
    console.log('\n👥 Users in database:')
    users.rows.forEach(user => {
      console.log(`- ID: "${user.id}" (type: ${typeof user.id}), Email: ${user.email}`)
    })

  } catch (error) {
    console.error('❌ Debug failed:', error)
  } finally {
    await db.end()
  }
}

debugRecentActivity()
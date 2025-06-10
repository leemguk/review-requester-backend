import { db } from '../src/lib/prisma'

const debugAuth = async () => {
  try {
    console.log('🔍 Checking users in database...')

    const result = await db.query(`
      SELECT id, email, name, "createdAt"
      FROM users 
      ORDER BY "createdAt" DESC
    `)

    console.log('👥 All users in database:')
    result.rows.forEach((user, index) => {
      console.log(`${index + 1}. ID: ${user.id} (type: ${typeof user.id})`)
      console.log(`   Email: ${user.email}`)
      console.log(`   Name: ${user.name}`)
      console.log(`   Created: ${user.createdAt}`)
      console.log('---')
    })

    console.log('\n📧 Emails and their user associations:')
    const emailsResult = await db.query(`
      SELECT e.id, e."to", e.status, e."userId", u.email as user_email
      FROM emails e
      LEFT JOIN users u ON e."userId" = u.id
      ORDER BY e."createdAt" DESC
    `)

    emailsResult.rows.forEach((email, index) => {
      console.log(`${index + 1}. Email to: ${email.to}`)
      console.log(`   Associated userId: ${email.userId} (type: ${typeof email.userId})`)
      console.log(`   User email: ${email.user_email || 'NO MATCH FOUND'}`)
      console.log('---')
    })

  } catch (error) {
    console.error('❌ Debug failed:', error)
  } finally {
    await db.end()
  }
}

debugAuth()
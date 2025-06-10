import { db } from '../src/lib/prisma'

const debugEmails = async () => {
  try {
    console.log('🔍 Checking emails in database...')

    const result = await db.query(`
      SELECT id, "to", status, "userId", "createdAt"
      FROM emails 
      ORDER BY "createdAt" DESC 
      LIMIT 5
    `)

    console.log('📧 Recent emails:')
    result.rows.forEach((email, index) => {
      console.log(`${index + 1}. To: ${email.to}`)
      console.log(`   Status: "${email.status}" (length: ${email.status.length})`)
      console.log(`   UserId: ${email.userId}`)
      console.log(`   Created: ${email.createdAt}`)
      console.log('---')
    })

    console.log('\n📊 Status counts:')
    const statusCounts = await db.query(`
      SELECT status, COUNT(*) as count 
      FROM emails 
      GROUP BY status
    `)
    statusCounts.rows.forEach(row => {
      console.log(`"${row.status}": ${row.count}`)
    })

  } catch (error) {
    console.error('❌ Debug failed:', error)
  } finally {
    await db.end()
  }
}

debugEmails()
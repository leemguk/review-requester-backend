import { db } from '../src/lib/prisma'

const debugDatabase = async () => {
  try {
    console.log('🔍 Checking database structure...')

    // Check what tables exist
    const tables = await db.query(`
      SELECT table_name 
      FROM information_schema.tables 
      WHERE table_schema = 'public'
    `)
    console.log('📋 Existing tables:', tables.rows.map(r => r.table_name))

    // Check emails table structure if it exists
    if (tables.rows.some(r => r.table_name === 'emails')) {
      const emailsStructure = await db.query(`
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'emails'
        ORDER BY ordinal_position
      `)
      console.log('📝 Emails table structure:')
      emailsStructure.rows.forEach(row => {
        console.log(`  - ${row.column_name}: ${row.data_type}`)
      })
    }

    // Check campaigns table structure if it exists
    if (tables.rows.some(r => r.table_name === 'campaigns')) {
      const campaignsStructure = await db.query(`
        SELECT column_name, data_type 
        FROM information_schema.columns 
        WHERE table_name = 'campaigns'
        ORDER BY ordinal_position
      `)
      console.log('📝 Campaigns table structure:')
      campaignsStructure.rows.forEach(row => {
        console.log(`  - ${row.column_name}: ${row.data_type}`)
      })
    }

  } catch (error) {
    console.error('❌ Debug failed:', error)
  } finally {
    await db.end()
  }
}

debugDatabase()
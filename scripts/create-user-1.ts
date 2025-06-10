import { db } from '../src/lib/prisma'

const createUser = async () => {
  try {
    await db.query(`
      INSERT INTO users (id, email, name, "createdAt", "updatedAt")
      VALUES ('1', 'admin@test.com', 'Admin User', NOW(), NOW())
      ON CONFLICT (email) DO NOTHING
    `)
    console.log('✅ User with ID 1 created')
    
    // Verify the user was created
    const result = await db.query('SELECT id, email, name FROM users WHERE id = $1', ['1'])
    if (result.rows.length > 0) {
      console.log('✅ Verified user:', result.rows[0])
    }
    
  } catch (error) {
    console.error('❌ Error:', error)
  } finally {
    await db.end()
  }
}

createUser()

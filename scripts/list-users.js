// Create this file as: scripts/list-users.js
const { Client } = require('pg');

async function listUsers() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
  });

  try {
    await client.connect();
    console.log('👥 All users in database:\n');

    const result = await client.query(`
      SELECT id, email, name, "createdAt"
      FROM users 
      ORDER BY "createdAt" DESC
    `);

    if (result.rows.length === 0) {
      console.log('No users found. You need to register first.');
    } else {
      result.rows.forEach((user, index) => {
        console.log(`${index + 1}. Email: ${user.email}`);
        console.log(`   Name: ${user.name}`);
        console.log(`   ID: ${user.id}`);
        console.log(`   Created: ${user.createdAt}`);
        console.log('---');
      });
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
  } finally {
    await client.end();
  }
}

listUsers();
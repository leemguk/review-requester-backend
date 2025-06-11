const { Client } = require('pg');

async function clearDatabase() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
  });

  try {
    await client.connect();
    console.log('🗑️  Clearing all data from database...\n');

    // Delete in correct order (due to foreign keys)
    await client.query('DELETE FROM emails');
    console.log('✅ Cleared emails table');

    await client.query('DELETE FROM campaigns');
    console.log('✅ Cleared campaigns table');

    await client.query('DELETE FROM user_email_settings');
    console.log('✅ Cleared user_email_settings table');

    await client.query('DELETE FROM users');
    console.log('✅ Cleared users table');

    console.log('\n🎉 All data cleared successfully!');

  } catch (error) {
    console.error('❌ Error:', error.message);
  } finally {
    await client.end();
  }
}

// Confirm before clearing
console.log('⚠️  WARNING: This will delete ALL data from your database!');
console.log('Press Ctrl+C to cancel, or wait 5 seconds to continue...\n');

setTimeout(() => {
  clearDatabase();
}, 5000);
const { Client } = require('pg');

async function cleanupOldUser() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
  });

  const OLD_USER_ID = '1749639689600';

  try {
    await client.connect();

    // Double-check no emails are left
    const checkResult = await client.query(
      'SELECT COUNT(*) as count FROM emails WHERE "userId" = $1',
      [OLD_USER_ID]
    );

    if (parseInt(checkResult.rows[0].count) > 0) {
      console.log('❌ Cannot delete user - still has emails associated!');
      return;
    }

    console.log('🗑️  Deleting old system user...');

    const deleteResult = await client.query(
      'DELETE FROM users WHERE id = $1 AND email = $2',
      [OLD_USER_ID, 'system@reviewrequester.com']
    );

    if (deleteResult.rowCount > 0) {
      console.log('✅ Old system user deleted successfully!');
    } else {
      console.log('ℹ️  User not found or already deleted.');
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
  } finally {
    await client.end();
  }
}

cleanupOldUser();
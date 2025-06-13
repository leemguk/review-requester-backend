const { Client } = require('pg');

async function migrateUserEmails() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
  });

  const OLD_USER_ID = '1749639689600';
  const NEW_USER_ID = '1749729236359';

  try {
    await client.connect();
    console.log('🔄 Starting email migration...\n');

    // First, check how many emails need to be migrated
    const checkResult = await client.query(
      'SELECT COUNT(*) as count FROM emails WHERE "userId" = $1',
      [OLD_USER_ID]
    );

    const emailCount = parseInt(checkResult.rows[0].count);
    console.log(`📧 Found ${emailCount} emails to migrate from user ${OLD_USER_ID} to ${NEW_USER_ID}\n`);

    if (emailCount === 0) {
      console.log('✅ No emails to migrate!');
      return;
    }

    // Show a sample of emails that will be migrated
    const sampleResult = await client.query(`
      SELECT id, "to", subject, status, "createdAt"
      FROM emails 
      WHERE "userId" = $1
      ORDER BY "createdAt" DESC
      LIMIT 5
    `, [OLD_USER_ID]);

    console.log('📋 Sample of emails to be migrated:');
    sampleResult.rows.forEach((email, index) => {
      console.log(`${index + 1}. To: ${email.to}, Status: ${email.status}, Created: ${email.createdAt}`);
    });

    // Ask for confirmation
    console.log(`\n⚠️  This will update ${emailCount} email records.`);
    console.log('Press Ctrl+C within 5 seconds to cancel...\n');

    await new Promise(resolve => setTimeout(resolve, 5000));

    // Perform the migration
    console.log('🚀 Migrating emails...');

    const updateResult = await client.query(`
      UPDATE emails 
      SET "userId" = $1, "updatedAt" = NOW()
      WHERE "userId" = $2
    `, [NEW_USER_ID, OLD_USER_ID]);

    console.log(`\n✅ Successfully migrated ${updateResult.rowCount} emails!`);

    // Verify the migration
    const verifyResult = await client.query(`
      SELECT 
        "userId",
        COUNT(*) as count
      FROM emails
      WHERE "userId" IN ($1, $2)
      GROUP BY "userId"
    `, [OLD_USER_ID, NEW_USER_ID]);

    console.log('\n📊 Post-migration email counts:');
    verifyResult.rows.forEach(row => {
      console.log(`User ID ${row.userId}: ${row.count} emails`);
    });

    // Check if we should also migrate email settings
    const settingsResult = await client.query(`
      SELECT * FROM user_email_settings WHERE user_id = $1
    `, [OLD_USER_ID]);

    if (settingsResult.rows.length > 0) {
      console.log('\n⚙️  Found email settings for old user ID. Migrating settings...');

      // Delete any existing settings for new user to avoid conflicts
      await client.query('DELETE FROM user_email_settings WHERE user_id = $1', [NEW_USER_ID]);

      // Update settings to new user
      await client.query(`
        UPDATE user_email_settings 
        SET user_id = $1, updated_at = NOW()
        WHERE user_id = $2
      `, [NEW_USER_ID, OLD_USER_ID]);

      console.log('✅ Email settings migrated!');
    }

    console.log('\n🎉 Migration complete!');

  } catch (error) {
    console.error('❌ Migration failed:', error.message);
  } finally {
    await client.end();
  }
}

migrateUserEmails();
cat > scripts/check-duplicate-users.js << 'EOF'
const { Client } = require('pg');

async function checkDuplicateUsers() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
  });

  try {
    await client.connect();
    console.log('🔍 Checking for duplicate users with email: lee.gilbert@ransomspares.co.uk\n');

    // Query 1: Find all users with this email
    const usersResult = await client.query(`
      SELECT 
        id,
        email,
        name,
        "createdAt",
        "updatedAt"
      FROM users 
      WHERE email = 'lee.gilbert@ransomspares.co.uk'
      ORDER BY "createdAt" DESC
    `);

    console.log('👥 Found users:');
    usersResult.rows.forEach((user, index) => {
      console.log(`\n${index + 1}. User ID: ${user.id}`);
      console.log(`   Name: ${user.name}`);
      console.log(`   Created: ${user.createdAt}`);
      console.log(`   Updated: ${user.updatedAt}`);
    });

    // Query 2: Check which user has sent emails
    const emailsResult = await client.query(`
      SELECT 
        u.id as user_id,
        COUNT(e.id) as email_count,
        MAX(e."createdAt") as last_email_sent
      FROM users u
      LEFT JOIN emails e ON u.id = e."userId"
      WHERE u.email = 'lee.gilbert@ransomspares.co.uk'
      GROUP BY u.id
      ORDER BY email_count DESC
    `);

    console.log('\n📧 Email activity by user:');
    emailsResult.rows.forEach(row => {
      console.log(`\nUser ID: ${row.user_id}`);
      console.log(`Emails sent: ${row.email_count}`);
      console.log(`Last email: ${row.last_email_sent || 'Never'}`);
    });

    // Query 3: Check email settings
    const settingsResult = await client.query(`
      SELECT 
        s.user_id,
        s.display_name,
        s.from_email,
        s.updated_at
      FROM user_email_settings s
      WHERE s.user_id IN (
        SELECT id FROM users WHERE email = 'lee.gilbert@ransomspares.co.uk'
      )
    `);

    if (settingsResult.rows.length > 0) {
      console.log('\n⚙️  Email settings:');
      settingsResult.rows.forEach(row => {
        console.log(`\nUser ID: ${row.user_id}`);
        console.log(`Display Name: ${row.display_name}`);
        console.log(`Last updated: ${row.updated_at}`);
      });
    }

    console.log('\n💡 Recommendation:');
    if (emailsResult.rows.length > 0) {
      const activeUser = emailsResult.rows[0];
      console.log(`The most active user ID is: ${activeUser.user_id} with ${activeUser.email_count} emails sent.`);

      if (usersResult.rows.length > 1) {
        console.log('\n⚠️  You have duplicate users! Consider deleting the inactive one(s).');
      }
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
  } finally {
    await client.end();
  }
}

checkDuplicateUsers();
EOF
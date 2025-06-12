const { Client } = require('pg');

async function addOrderNumberColumn() {
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
  });

  try {
    await client.connect();
    console.log('🔄 Adding orderNumber column to emails table...');

    // Add the column
    await client.query(`
      ALTER TABLE emails 
      ADD COLUMN IF NOT EXISTS "orderNumber" VARCHAR(255)
    `);
    console.log('✅ Added orderNumber column');

    // Create an index for faster lookups
    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_emails_orderNumber 
      ON emails("orderNumber")
    `);
    console.log('✅ Created index on orderNumber');

    console.log('🎉 Database updated successfully!');

  } catch (error) {
    console.error('❌ Error:', error.message);
  } finally {
    await client.end();
  }
}

addOrderNumberColumn();
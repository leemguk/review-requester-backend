// setup-staging-db.js
// This script copies your production database structure to staging
// Run this ONCE to set up your staging database

const { Client } = require('pg');

// ⚠️ UPDATE THIS WITH YOUR STAGING CONNECTION STRING!
const STAGING_DB = 'postgresql://postgres.znzvtokuntyatdjdmlom:84qjDLGNseNEiK@aws-0-eu-west-2.pooler.supabase.com:5432/postgres';

async function setupStagingDatabase() {
  // Production DB from environment
  const PRODUCTION_DB = process.env.DATABASE_URL;

  if (!PRODUCTION_DB) {
    console.error('❌ No DATABASE_URL found in environment!');
    return;
  }

  if (STAGING_DB.includes('YOUR_PROJECT_ID')) {
    console.error('❌ Please update STAGING_DB with your actual connection string!');
    return;
  }

  const prodClient = new Client({ connectionString: PRODUCTION_DB });
  const stagingClient = new Client({ connectionString: STAGING_DB });

  try {
    console.log('🚀 Starting staging database setup...\n');

    await prodClient.connect();
    console.log('✅ Connected to production database');

    await stagingClient.connect();
    console.log('✅ Connected to staging database\n');

    // 1. Copy all tables structure
    console.log('📋 Copying table structures...\n');

    // Get the exact CREATE TABLE statements from production
    const tables = ['users', 'emails', 'campaigns', 'user_email_settings'];

    for (const tableName of tables) {
      console.log(`Creating ${tableName}...`);

      // Get column definitions
      const columnsQuery = `
        SELECT 
          column_name,
          data_type,
          character_maximum_length,
          column_default,
          is_nullable
        FROM information_schema.columns
        WHERE table_schema = 'public' 
          AND table_name = $1
        ORDER BY ordinal_position
      `;

      const columns = await prodClient.query(columnsQuery, [tableName]);

      // Build CREATE TABLE statement
      let createTableSQL = `CREATE TABLE IF NOT EXISTS ${tableName} (\n`;
      const columnDefs = [];

      for (const col of columns.rows) {
        let colDef = `  "${col.column_name}" `;

        // Map data types
        switch (col.data_type) {
          case 'character varying':
            colDef += `VARCHAR(${col.character_maximum_length || 255})`;
            break;
          case 'timestamp with time zone':
            colDef += 'TIMESTAMPTZ';
            break;
          case 'timestamp without time zone':
            colDef += 'TIMESTAMP';
            break;
          case 'integer':
            colDef += 'INTEGER';
            break;
          case 'bigint':
            colDef += 'BIGINT';
            break;
          case 'text':
            colDef += 'TEXT';
            break;
          case 'boolean':
            colDef += 'BOOLEAN';
            break;
          default:
            colDef += col.data_type.toUpperCase();
        }

        // Add constraints
        if (col.is_nullable === 'NO') {
          colDef += ' NOT NULL';
        }

        if (col.column_default) {
          // Handle auto-increment
          if (col.column_default.includes('nextval')) {
            if (col.data_type === 'integer') {
              colDef = `  "${col.column_name}" SERIAL`;
              if (col.is_nullable === 'NO') {
                colDef += ' NOT NULL';
              }
            }
          } else {
            colDef += ` DEFAULT ${col.column_default}`;
          }
        }

        columnDefs.push(colDef);
      }

      createTableSQL += columnDefs.join(',\n');
      createTableSQL += '\n);';

      // Create the table
      try {
        await stagingClient.query(createTableSQL);
        console.log(`✅ Created table: ${tableName}`);
      } catch (error) {
        if (error.message.includes('already exists')) {
          console.log(`⚠️  Table ${tableName} already exists`);
        } else {
          console.error(`❌ Error creating ${tableName}:`, error.message);
        }
      }
    }

    // 2. Copy constraints
    console.log('\n🔗 Copying constraints...\n');

    // Primary keys
    const pkQuery = `
      SELECT 
        tc.table_name,
        tc.constraint_name,
        string_agg(kcu.column_name, ', ') as columns
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu
        ON tc.constraint_name = kcu.constraint_name
      WHERE tc.table_schema = 'public'
        AND tc.constraint_type = 'PRIMARY KEY'
        AND tc.table_name IN ('users', 'emails', 'campaigns', 'user_email_settings')
      GROUP BY tc.table_name, tc.constraint_name
    `;

    const primaryKeys = await prodClient.query(pkQuery);

    for (const pk of primaryKeys.rows) {
      try {
        const alterSQL = `ALTER TABLE ${pk.table_name} ADD PRIMARY KEY (${pk.columns})`;
        await stagingClient.query(alterSQL);
        console.log(`✅ Added primary key to ${pk.table_name}`);
      } catch (error) {
        if (error.message.includes('already exists')) {
          console.log(`⚠️  Primary key already exists on ${pk.table_name}`);
        } else {
          console.log(`⚠️  Could not add primary key to ${pk.table_name}: ${error.message}`);
        }
      }
    }

    // Foreign keys
    const fkQuery = `
      SELECT DISTINCT
        tc.table_name,
        tc.constraint_name,
        kcu.column_name,
        ccu.table_name AS foreign_table_name,
        ccu.column_name AS foreign_column_name
      FROM information_schema.table_constraints tc
      JOIN information_schema.key_column_usage kcu
        ON tc.constraint_name = kcu.constraint_name
      JOIN information_schema.constraint_column_usage ccu
        ON ccu.constraint_name = tc.constraint_name
      WHERE tc.constraint_type = 'FOREIGN KEY'
        AND tc.table_schema = 'public'
    `;

    const foreignKeys = await prodClient.query(fkQuery);

    for (const fk of foreignKeys.rows) {
      try {
        const alterSQL = `
          ALTER TABLE ${fk.table_name} 
          ADD CONSTRAINT ${fk.constraint_name} 
          FOREIGN KEY ("${fk.column_name}") 
          REFERENCES ${fk.foreign_table_name}(${fk.foreign_column_name})
        `;
        await stagingClient.query(alterSQL);
        console.log(`✅ Added foreign key: ${fk.constraint_name}`);
      } catch (error) {
        if (error.message.includes('already exists')) {
          console.log(`⚠️  Foreign key ${fk.constraint_name} already exists`);
        } else {
          console.log(`⚠️  Could not add foreign key ${fk.constraint_name}: ${error.message}`);
        }
      }
    }

    // 3. Create indexes
    console.log('\n📊 Creating indexes...\n');

    const indexes = [
      'CREATE INDEX IF NOT EXISTS idx_emails_userId ON emails("userId")',
      'CREATE INDEX IF NOT EXISTS idx_emails_status ON emails(status)',
      'CREATE INDEX IF NOT EXISTS idx_emails_createdAt ON emails("createdAt")',
      'CREATE INDEX IF NOT EXISTS idx_campaigns_userId ON campaigns("userId")',
      'CREATE INDEX IF NOT EXISTS idx_user_email_settings_user_id ON user_email_settings(user_id)'
    ];

    for (const indexSQL of indexes) {
      try {
        await stagingClient.query(indexSQL);
        console.log(`✅ Created index`);
      } catch (error) {
        console.log(`⚠️  Index might already exist: ${error.message}`);
      }
    }

    // 4. Create test user
    console.log('\n👤 Creating test user...\n');

    const bcrypt = require('bcrypt');
    const hashedPassword = await bcrypt.hash('TestPassword123!', 12);

    try {
      await stagingClient.query(`
        INSERT INTO users (id, email, name, password, "createdAt", "updatedAt")
        VALUES ($1, $2, $3, $4, NOW(), NOW())
      `, [
        Date.now().toString(),
        'test@ransomspares.co.uk',
        'Test User',
        hashedPassword
      ]);
      console.log('✅ Test user created successfully!');
    } catch (error) {
      if (error.message.includes('duplicate key')) {
        console.log('⚠️  Test user already exists');
      } else {
        console.error('❌ Could not create test user:', error.message);
      }
    }

    // Success!
    console.log('\n' + '='.repeat(60));
    console.log('🎉 STAGING DATABASE SETUP COMPLETE!');
    console.log('='.repeat(60));
    console.log('\n📝 Test User Credentials:');
    console.log('   Email: test@ransomspares.co.uk');
    console.log('   Password: TestPassword123!');
    console.log('\n🔗 Staging Connection String:');
    console.log(`   ${STAGING_DB.replace(/:[^@]+@/, ':****@')}`);
    console.log('\n✅ Next Steps:');
    console.log('   1. Fork your Replit project');
    console.log('   2. Update DATABASE_URL in the forked Replit');
    console.log('   3. Start developing safely!');

  } catch (error) {
    console.error('\n❌ Setup failed:', error.message);
    console.error('Details:', error);
  } finally {
    await prodClient.end();
    await stagingClient.end();
  }
}

// Show what we're about to do
console.log('='.repeat(60));
console.log('STAGING DATABASE SETUP');
console.log('='.repeat(60));
console.log('\nThis script will:');
console.log('✓ Copy all table structures from production');
console.log('✓ Copy constraints and relationships');
console.log('✓ Create indexes for performance');
console.log('✓ Create a test user account');
console.log('✗ NOT copy any production data\n');

// Safety check
if (STAGING_DB.includes('YOUR_PROJECT_ID')) {
  console.error('❌ ERROR: Please update STAGING_DB with your actual connection string!');
  console.log('\nEdit this file and replace the STAGING_DB value with your');
  console.log('Supabase staging connection string (Session Pooler format).\n');
  process.exit(1);
}

console.log('📦 Using staging database:');
console.log(`   ${STAGING_DB.replace(/:[^@]+@/, ':****@')}\n`);
console.log('Press Ctrl+C to cancel, or wait 5 seconds to continue...\n');

setTimeout(() => {
  setupStagingDatabase();
}, 5000);
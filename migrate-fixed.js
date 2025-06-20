const { Client } = require('pg');

// Hardcode the Supabase connection to bypass environment variable issues
const config = {
  neon: {
    connectionString: process.env.DATABASE_URL || process.env.NEON_DATABASE_URL
  },
  supabase: {
    connectionString: 'postgresql://postgres.nhzsuvzjhmsjknqgtcep:7p5H3CDKBtrn4j@aws-0-eu-west-2.pooler.supabase.com:5432/postgres'
  }
};

// Validate Neon connection
if (!config.neon.connectionString) {
  console.error('ERROR: Neon database URL not found in secrets!');
  process.exit(1);
}

// Create clients
const neonClient = new Client({ connectionString: config.neon.connectionString });
const supabaseClient = new Client({ connectionString: config.supabase.connectionString });

async function migrate() {
  try {
    // Connect to both databases
    console.log('Connecting to databases...');
    console.log('Using hardcoded Supabase URL');

    await neonClient.connect();
    console.log('✓ Connected to Neon database');

    await supabaseClient.connect();
    console.log('✓ Connected to Supabase database');

    // Get all tables from Neon (excluding system tables)
    const tablesQuery = `
      SELECT tablename 
      FROM pg_tables 
      WHERE schemaname = 'public'
      ORDER BY tablename;
    `;

    const { rows: tables } = await neonClient.query(tablesQuery);
    console.log(`\nFound ${tables.length} tables to migrate:`, tables.map(t => t.tablename).join(', '));

    // Process each table
    for (const { tablename } of tables) {
      console.log(`\n━━━ Processing table: ${tablename} ━━━`);

      // Get table structure from Neon
      const structureQuery = `
        SELECT 
          column_name,
          data_type,
          character_maximum_length,
          is_nullable,
          column_default,
          udt_name
        FROM information_schema.columns
        WHERE table_schema = 'public' 
          AND table_name = $1
        ORDER BY ordinal_position;
      `;

      const { rows: columns } = await neonClient.query(structureQuery, [tablename]);
      console.log(`Found ${columns.length} columns`);

      // Store column info for later use
      const columnInfo = {};
      columns.forEach(col => {
        columnInfo[col.column_name] = {
          data_type: col.data_type,
          udt_name: col.udt_name
        };
      });

      // Build CREATE TABLE statement
      let createTableSQL = `CREATE TABLE IF NOT EXISTS ${tablename} (\n`;
      const columnDefinitions = [];

      for (const col of columns) {
        let colDef = `  "${col.column_name}" `;

        // Map data types
        if (col.data_type === 'character varying') {
          colDef += `VARCHAR(${col.character_maximum_length || 255})`;
        } else if (col.data_type === 'integer' && col.column_default && col.column_default.includes('nextval')) {
          colDef += 'SERIAL';
        } else if (col.data_type === 'bigint' && col.column_default && col.column_default.includes('nextval')) {
          colDef += 'BIGSERIAL';
        } else if (col.data_type === 'text') {
          colDef += 'TEXT';
        } else if (col.data_type === 'boolean') {
          colDef += 'BOOLEAN';
        } else if (col.data_type === 'timestamp with time zone') {
          colDef += 'TIMESTAMPTZ';
        } else if (col.data_type === 'timestamp without time zone') {
          colDef += 'TIMESTAMP';
        } else if (col.data_type === 'json') {
          colDef += 'JSON';
        } else if (col.data_type === 'jsonb') {
          colDef += 'JSONB';
        } else {
          colDef += col.udt_name.toUpperCase();
        }

        // Add constraints
        if (col.is_nullable === 'NO') {
          colDef += ' NOT NULL';
        }

        // Handle defaults (but not for SERIAL)
        if (col.column_default && !col.column_default.includes('nextval')) {
          colDef += ` DEFAULT ${col.column_default}`;
        }

        columnDefinitions.push(colDef);
      }

      // Get primary key information
      const pkQuery = `
        SELECT column_name
        FROM information_schema.key_column_usage
        WHERE table_schema = 'public' 
          AND table_name = $1
          AND constraint_name LIKE '%_pkey';
      `;

      const { rows: pkColumns } = await neonClient.query(pkQuery, [tablename]);
      if (pkColumns.length > 0) {
        columnDefinitions.push(`  PRIMARY KEY (${pkColumns.map(pk => pk.column_name).join(', ')})`);
      }

      createTableSQL += columnDefinitions.join(',\n');
      createTableSQL += '\n);';

      // Create table in Supabase
      console.log(`Creating table in Supabase...`);
      try {
        await supabaseClient.query(createTableSQL);
        console.log(`✓ Table ${tablename} created successfully!`);
      } catch (error) {
        if (error.message.includes('already exists')) {
          console.log(`⚠ Table ${tablename} already exists, skipping creation.`);
        } else {
          throw error;
        }
      }

      // Copy data from Neon to Supabase
      console.log(`Copying data from Neon to Supabase...`);

      // First, clear any existing data in Supabase table
      await supabaseClient.query(`TRUNCATE TABLE ${tablename} RESTART IDENTITY CASCADE;`);

      // Get all data from Neon
      const { rows: data } = await neonClient.query(`SELECT * FROM ${tablename}`);
      console.log(`Found ${data.length} rows to copy`);

      if (data.length > 0) {
        // Debug first row
        if (tablename === 'emails') {
          console.log('First row sample:');
          Object.entries(data[0]).slice(0, 5).forEach(([k, v]) => {
            console.log(`  ${k}: ${typeof v} = ${v}`);
          });
        }

        // Build INSERT statement with proper type handling
        const columnNames = Object.keys(data[0]);
        const quotedColumnNames = columnNames.map(col => `"${col}"`);

        // Prepare the INSERT statement
        let insertSQL = `INSERT INTO ${tablename} (${quotedColumnNames.join(', ')}) VALUES (`;

        // Build placeholders with type conversions
        const placeholders = columnNames.map((col, idx) => {
          const colData = columnInfo[col];
          if (!colData) return `$${idx + 1}`;

          // Check if this is a timestamp column with integer data
          if ((colData.data_type === 'timestamp without time zone' || 
               colData.data_type === 'timestamp with time zone') &&
              typeof data[0][col] === 'number') {
            // Convert Unix timestamp to PostgreSQL timestamp
            // Check if it's milliseconds or seconds
            const sampleValue = data[0][col];
            if (sampleValue > 9999999999) {
              // Milliseconds
              return `to_timestamp($${idx + 1}::bigint / 1000.0)`;
            } else {
              // Seconds
              return `to_timestamp($${idx + 1}::bigint)`;
            }
          }

          return `$${idx + 1}`;
        });

        insertSQL += placeholders.join(', ') + ')';

        console.log('Using INSERT SQL:', insertSQL);

        // Insert in batches for better performance
        const batchSize = 100;
        for (let i = 0; i < data.length; i += batchSize) {
          const batch = data.slice(i, i + batchSize);

          // Use a transaction for each batch
          await supabaseClient.query('BEGIN');
          try {
            for (const row of batch) {
              const values = columnNames.map(col => row[col]);
              await supabaseClient.query(insertSQL, values);
            }
            await supabaseClient.query('COMMIT');
            console.log(`✓ Copied rows ${i + 1}-${Math.min(i + batchSize, data.length)} of ${data.length}`);
          } catch (error) {
            await supabaseClient.query('ROLLBACK');
            console.error(`Error in batch starting at row ${i + 1}:`, error.message);
            // Log the problematic row for debugging
            if (batch.length > 0) {
              console.log('First row in failed batch:', batch[0]);
            }
            throw error;
          }
        }

        // Update sequences for SERIAL columns
        for (const col of columns) {
          if (col.column_default && col.column_default.includes('nextval')) {
            const sequenceName = `${tablename}_${col.column_name}_seq`;
            try {
              await supabaseClient.query(`
                SELECT setval('${sequenceName}', (SELECT COALESCE(MAX("${col.column_name}"), 0) FROM ${tablename}));
              `);
              console.log(`✓ Updated sequence for ${col.column_name}`);
            } catch (e) {
              console.log(`⚠ Could not update sequence ${sequenceName}: ${e.message}`);
            }
          }
        }
      }
    }

    console.log('\n━━━ Migration completed successfully! ━━━');

    // Verify data
    console.log('\n━━━ Verification ━━━');
    let allMatch = true;
    for (const { tablename } of tables) {
      const neonCount = await neonClient.query(`SELECT COUNT(*) FROM ${tablename}`);
      const supabaseCount = await supabaseClient.query(`SELECT COUNT(*) FROM ${tablename}`);
      const neonRows = neonCount.rows[0].count;
      const supabaseRows = supabaseCount.rows[0].count;
      const match = neonRows === supabaseRows ? '✓' : '✗';

      console.log(`${match} ${tablename}: Neon=${neonRows}, Supabase=${supabaseRows}`);

      if (neonRows !== supabaseRows) {
        allMatch = false;
      }
    }

    if (allMatch) {
      console.log('\n✓ All tables migrated successfully with matching row counts!');
      console.log('\nNext steps:');
      console.log('1. Test your application with Supabase');
      console.log('2. Update your app to use the Supabase connection');
      console.log('3. Once verified, you can remove the Neon connection');
    } else {
      console.log('\n⚠ Warning: Some tables have mismatched row counts. Please investigate.');
    }

  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    console.error('Full error:', error);
  } finally {
    // Close connections
    await neonClient.end();
    await supabaseClient.end();
    console.log('\nDatabase connections closed.');
  }
}

// Main execution
async function main() {
  console.log('Neon to Supabase Migration Script');
  console.log('==================================\n');

  console.log('Testing connections...');

  // Quick connection test
  try {
    const testClient = new Client({ connectionString: config.supabase.connectionString });
    await testClient.connect();
    console.log('✓ Supabase connection successful');
    await testClient.end();
  } catch (error) {
    console.error('✗ Supabase connection failed:', error.message);
    process.exit(1);
  }

  console.log('\nStarting migration...\n');
  await migrate();
}

// Run the script
main();
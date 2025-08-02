const { Pool } = require('pg');

if (!process.env.POSTGRES_URL) {
  throw new Error('Vercel Postgres URL is not set in environment variables.');
}

const pool = new Pool({
  connectionString: process.env.POSTGRES_URL,
  ssl: {
    rejectUnauthorized: false
  }
});

async function testConnection() {
  let client;
  try {
    client = await pool.connect();
    console.log('Successfully connected to Vercel Postgres (Neon)!');
  } catch (error) {
    console.error('Error connecting to Vercel Postgres:', error);
  } finally {
    if (client) client.release();
  }
}

testConnection();

module.exports = pool;
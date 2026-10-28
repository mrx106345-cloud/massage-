import 'dotenv/config';
import { db } from './db/index.js';

const direction = process.argv[2] === 'down' ? 'down' : 'up';

async function main() {
  if (direction === 'down') {
    console.log('Rolling back migration 0001...');
    try {
      await (await import('./db/migrations/0001_initial_schema.js')).down();
      console.log('Migration rolled back.');
    } catch (err) {
      console.error('Rollback failed:', err);
      process.exit(1);
    }
  } else {
    console.log('Running migration 0001 (up)...');
    try {
      await (await import('./db/migrations/0001_initial_schema.js')).up();
      console.log('Migration applied.');
    } catch (err) {
      console.error('Migration failed:', err);
      process.exit(1);
    }
  }
}

main()
  .catch((err) => {
    console.error(err);
    process.exit(1);
  })
  .finally(async () => {
    await db.destroy().catch(() => undefined);
  });

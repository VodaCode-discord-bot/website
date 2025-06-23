const bcrypt = require('bcryptjs');
const fs = require('fs');
const SALT_ROUNDS = 12;

const users = JSON.parse(fs.readFileSync('./data/settings/users.json'));

async function migrate() {
  for (const [username, password] of Object.entries(users)) {
    if (!password.startsWith('$2a$')) { // Alleen hashen als het nog plaintext is
      users[username] = await bcrypt.hash(password, SALT_ROUNDS);
    }
  }
  fs.writeFileSync('./settings/users.json', JSON.stringify(users, null, 2));
  console.log('Migratie voltooid!');
}

migrate();
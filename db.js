import sqlite3pkg from 'sqlite3';
import path from 'node:path';
import { fileURLToPath } from 'node:url';;

const sqlite3 = sqlite3pkg.verbose();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbPath = path.join(__dirname, 'demo.db');
const db = new sqlite3.Database(dbPath);

db.serialize(() => {
  db.run("DROP TABLE IF EXISTS users");
  db.run(`
    CREATE TABLE users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    )
  `);

  const stmt = db.prepare(
    "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
  );
  stmt.run("admin", "admin123", "admin");
  stmt.run("gilberto", "1234", "user");
  stmt.finalize();

  console.log("Base de datos creada");
});

db.close();
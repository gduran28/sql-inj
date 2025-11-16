import express from 'express';
import sqlite3pkg from 'sqlite3';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const sqlite3 = sqlite3pkg.verbose();
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const dbPath = path.join(__dirname, 'demo.db');
const db = new sqlite3.Database(dbPath);

const app = express();
const port = 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.get('/', (req, res) => {
  res.send(`
    <h1>Demo SQL Injection (lab local)</h1>
    <p>Datos de prueba:</p>
    <ul>
      <li>Usuario: <code>admin</code> / Password: <code>admin123</code></li>
      <li>Usuario: <code>gilberto</code> / Password: <code>1234</code></li>
    </ul>
    <form method="POST" action="/login">
      <label>Usuario: <input type="text" name="username" /></label><br/>
      <label>Password: <input type="password" name="password" /></label><br/>
      <button type="submit">Iniciar sesión (inseguro)</button>
    </form>

    <hr/>

    <form method="POST" action="/login-safe">
      <label>Usuario: <input type="text" name="username" /></label><br/>
      <label>Password: <input type="password" name="password" /></label><br/>
      <button type="submit">Iniciar sesión (seguro)</button>
    </form>
    `);
});

app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  console.log('Ejecutando consulta insegura:', query);
  console.log('query:', query);

  db.get(query, (err, row) => {
    if (err) {
      res.status(500).send('Error en la base de datos');
      return;
    }
    if (row) {
      res.send(`¡Bienvenido, ${row.username}! (Inseguro)`);
    } else {
      res.send('Credenciales inválidas (Inseguro)');
    }
  });
});

app.post('/login-safe', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
  console.log('Ejecutando consulta segura:', query);

  db.get(query, [username, password], (err, row) => {
    if (err) {
      res.status(500).send('Error en la base de datos');
      return;
    }
    if (row) {
      res.send(`¡Bienvenido, ${row.username}! (Seguro)`);
    } else {
      res.send('Credenciales inválidas (Seguro)');
    }
  })
});

app.listen(port, () => {
  console.log(`Servidor escuchando en http://localhost:${port}`);
});
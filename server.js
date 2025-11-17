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

// SISTEMA DE DETECCIÓN
const attackPatterns = [
  { pattern: /(\bOR\b|\bAND\b).*=.*=/gi, name: "Operador Lógico Sospechoso" },
  { pattern: /--/g, name: "Comentario SQL" },
  { pattern: /;.*DROP/gi, name: "Intento de DROP TABLE" },
  { pattern: /UNION.*SELECT/gi, name: "UNION-based Injection" },
  { pattern: /'/g, name: "Comillas Simples" },
  { pattern: /1=1/gi, name: "Condición Siempre Verdadera" }
];

let attackLogs = [];

function detectSQLInjection(input) {
  const detectedPatterns = [];
  for (const { pattern, name } of attackPatterns) {
    if (pattern.test(input)) detectedPatterns.push(name);
  }
  return { isAttack: detectedPatterns.length > 0, patterns: detectedPatterns };
}

function logAttempt(type, username, password, result, query = null) {
  const detection = detectSQLInjection(username + ' ' + password);
  const log = {
    timestamp: new Date().toISOString(),
    type, username, password, result,
    isAttack: detection.isAttack,
    detectedPatterns: detection.patterns,
    query
  };
  attackLogs.push(log);
  if (attackLogs.length > 100) attackLogs.shift();
  
  if (detection.isAttack) {
    console.log('\nALERTA:', username, '|', detection.patterns.join(', '));
  }
}

const sharedStyles = `
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: #ffffff;
    color: #1a1a1a;
    line-height: 1.6;
    min-height: 100vh;
    padding: 40px 20px;
  }
  .container { max-width: 1200px; margin: 0 auto; }
  .header {
    text-align: center;
    margin-bottom: 60px;
    padding-bottom: 30px;
    border-bottom: 1px solid #e5e5e5;
  }
  .header h1 {
    font-size: 2.5rem;
    font-weight: 700;
    margin-bottom: 12px;
    background: linear-gradient(135deg, #000000 0%, #666666 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }
  .header p { color: #666; font-size: 0.95rem; }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(500px, 1fr));
    gap: 30px;
    margin-bottom: 40px;
  }
  .card {
    background: #fafafa;
    border: 1px solid #e5e5e5;
    border-radius: 16px;
    padding: 35px;
    transition: all 0.3s;
  }
  .card:hover { 
    border-color: #d0d0d0; 
    transform: translateY(-2px);
    box-shadow: 0 4px 12px rgba(0,0,0,0.05);
  }
  .card-header {
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 25px;
    padding-bottom: 20px;
    border-bottom: 1px solid #e5e5e5;
  }
  .card-header h2 { font-size: 1.3rem; font-weight: 600; color: #1a1a1a; }
  .badge {
    padding: 4px 12px;
    border-radius: 6px;
    font-size: 0.7rem;
    font-weight: 600;
    text-transform: uppercase;
  }
  .badge.vulnerable { 
    background: #f5f5f5; 
    color: #666; 
    border: 1px solid #e0e0e0; 
  }
  .badge.secure { 
    background: #1a1a1a; 
    color: #fff; 
    border: 1px solid #1a1a1a; 
  }
  .info-box {
    background: #ffffff;
    border: 1px solid #e5e5e5;
    border-radius: 10px;
    padding: 16px;
    margin-bottom: 20px;
    font-size: 0.85rem;
  }
  .info-box strong { 
    display: block; 
    margin-bottom: 8px; 
    color: #1a1a1a;
    font-weight: 600;
  }
  .info-box ul { list-style: none; padding: 0; }
  .info-box li { padding: 6px 0; color: #666; }
  .info-box code {
    background: #f5f5f5;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.8rem;
    color: #1a1a1a;
    border: 1px solid #e5e5e5;
  }
  form { display: flex; flex-direction: column; gap: 18px; }
  label {
    display: flex;
    flex-direction: column;
    gap: 8px;
    font-size: 0.9rem;
    font-weight: 500;
    color: #333;
  }
  input {
    padding: 14px 16px;
    background: #ffffff;
    border: 1px solid #d0d0d0;
    border-radius: 8px;
    color: #1a1a1a;
    font-size: 0.95rem;
    font-family: inherit;
  }
  input:focus { 
    outline: none; 
    border-color: #999; 
    box-shadow: 0 0 0 3px rgba(0,0,0,0.05);
  }
  input::placeholder { color: #aaa; }
  button {
    padding: 14px 24px;
    border: 1px solid #d0d0d0;
    border-radius: 8px;
    font-size: 0.95rem;
    font-weight: 500;
    cursor: pointer;
    font-family: inherit;
    margin-top: 8px;
    transition: all 0.2s;
  }
  .btn-vulnerable { 
    background: #ffffff; 
    color: #666; 
    border-color: #d0d0d0; 
  }
  .btn-vulnerable:hover { 
    background: #f5f5f5; 
    color: #333;
    border-color: #bbb;
  }
  .btn-secure { 
    background: #1a1a1a; 
    color: #fff;
    border-color: #1a1a1a;
  }
  .btn-secure:hover { 
    background: #333;
    border-color: #333;
  }
  .icon { 
    display: inline-block; 
    width: 8px; 
    height: 8px; 
    border-radius: 50%; 
    margin-right: 8px; 
  }
  .icon.vulnerable { background: #bbb; }
  .icon.secure { background: #1a1a1a; }
  @media (max-width: 1100px) { .grid { grid-template-columns: 1fr; } }
`;

// PÁGINA PRINCIPAL
app.get('/', (req, res) => {
  res.send(`<!DOCTYPE html>
    <html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQL Injection Lab</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>${sharedStyles}
      .monitor-section {
        background: #fafafa;
        border: 1px solid #e5e5e5;
        border-radius: 16px;
        padding: 35px;
        text-align: center;
      }
      .monitor-section h3 {
        margin-bottom: 20px;
        color: #1a1a1a;
        font-weight: 600;
      }
      .monitor-link {
        display: inline-block;
        padding: 14px 32px;
        background: #1a1a1a;
        color: #fff;
        text-decoration: none;
        border-radius: 8px;
        font-weight: 500;
        transition: all 0.2s;
      }
      .monitor-link:hover { 
        background: #333;
        transform: translateY(-1px);
      }
    </style></head><body>
    <div class="container">
      <div class="header">
        <h1>INYECCIONES SQL</h1>
        <p>Demostración de vulnerabilidades y defensas</p>
      </div>
      <div class="grid">
        <div class="card">
          <div class="card-header">
            <span class="icon vulnerable"></span>
            <h2>Endpoint Vulnerable</h2>
            <span class="badge vulnerable">Inseguro</span>
          </div>
          <div class="info-box">
            <strong>Credenciales de prueba</strong>
            <ul><li><code>admin</code> / <code>admin123</code></li>
          </div>
          <div class="info-box">
            <strong>Payloads de ataque</strong>
            <ul><li><code>admin' OR '1'='1</code></li>
            <li><code>admin'--</code></li>
            <li><code>' OR 1=1--</code></li></ul>
          </div>
          <form method="POST" action="/login">
            <label>Usuario<input type="text" name="username" placeholder="Ingresa usuario" /></label>
            <label>Contraseña<input type="password" name="password" placeholder="Ingresa contraseña" /></label>
            <button type="submit" class="btn-vulnerable">Iniciar sesión</button>
          </form>
        </div>
        <div class="card">
          <div class="card-header">
            <span class="icon secure"></span>
            <h2>Endpoint Protegido</h2>
            <span class="badge secure">Seguro</span>
          </div>
          <div class="info-box">
            <strong>Mecanismos de defensa</strong>
            <ul><li>Prepared Statements</li>
            <li>Validación de entrada</li>
            <li>Detección de patrones</li></ul>
          </div>
          <form method="POST" action="/login-safe">
            <label>Usuario<input type="text" name="username" placeholder="Ingresa usuario" /></label>
            <label>Contraseña<input type="password" name="password" placeholder="Ingresa contraseña" /></label>
            <button type="submit" class="btn-secure">Iniciar sesión</button>
          </form>
        </div>
      </div>
      <div class="monitor-section">
        <h3>Monitoreo en Tiempo Real</h3>
        <a href="/monitor" class="monitor-link">Ver Dashboard</a>
      </div>
    </div></body></html>`);
});

// ENDPOINTS
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
  db.get(query, (err, row) => {
    if (err) {
      logAttempt('vulnerable', username, password, 'error', query);
      return res.status(500).send(resultPage('Error', 'Error en BD'));
    }
    if (row) {
      logAttempt('vulnerable', username, password, 'success', query);
      res.send(resultPage('Acceso', `¡Bienvenido, ${row.username}!`, `⚠️ VULNERABLE | Rol: ${row.role}`));
    } else {
      logAttempt('vulnerable', username, password, 'failed', query);
      res.send(resultPage('Denegado', 'Credenciales inválidas', 'Endpoint vulnerable'));
    }
  });
});

app.post('/login-safe', (req, res) => {
  const { username, password } = req.body;
  const query = `SELECT * FROM users WHERE username = ? AND password = ?`;
  db.get(query, [username, password], (err, row) => {
    if (err) {
      logAttempt('safe', username, password, 'error');
      return res.status(500).send(resultPage('Error', 'Error en BD'));
    }
    if (row) {
      logAttempt('safe', username, password, 'success');
      res.send(resultPage('Acceso', `¡Bienvenido, ${row.username}!`, `🛡️ SEGURO | Rol: ${row.role}`, true));
    } else {
      logAttempt('safe', username, password, 'failed');
      res.send(resultPage('Denegado', 'Credenciales inválidas', 'Endpoint seguro'));
    }
  });
});

function resultPage(title, text, sub = '', ok = false) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@500;600&display=swap" rel="stylesheet">
    <style>
      body{
        font-family:'Inter',sans-serif;
        background:#ffffff;
        color:#1a1a1a;
        display:flex;
        align-items:center;
        justify-content:center;
        min-height:100vh;
        padding:20px
      }
      .r{
        max-width:500px;
        background:#fafafa;
        border:1px solid #e5e5e5;
        border-radius:16px;
        padding:40px;
        text-align:center;
        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
      }
      h1{
        margin-bottom:20px;
        color:${ok?'#1a1a1a':'#666'};
        font-weight:600
      }
      .i{
        background:${ok?'#f5f5f5':'#ffffff'};
        padding:15px;
        border-radius:8px;
        margin:20px 0;
        color:#666;
        font-size:0.9rem;
        border: 1px solid #e5e5e5;
      }
      a{
        display:inline-block;
        margin-top:20px;
        padding:12px 24px;
        background:#1a1a1a;
        color:#fff;
        text-decoration:none;
        border-radius:8px;
        font-weight:500;
        transition: all 0.2s;
      }
      a:hover {
        background: #333;
      }
    </style></head><body>
    <div class="r"><h1>${text}</h1>${sub?`<div class="i">${sub}</div>`:''}<a href="/">← Volver</a></div>
    </body></html>`;
}

// MONITOR
app.get('/monitor', (req, res) => {
  const attacks = attackLogs.filter(l => l.isAttack);
  const legit = attackLogs.filter(l => !l.isAttack);
  res.send(`<!DOCTYPE html><html><head><meta charset="UTF-8">
    <title>Dashboard</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&family=JetBrains+Mono:wght@400&display=swap" rel="stylesheet">
    <style>
      *{margin:0;padding:0;box-sizing:border-box}
      body{
        font-family:'Inter',sans-serif;
        background:#ffffff;
        color:#1a1a1a;
        padding:40px 20px
      }
      .c{max-width:1400px;margin:0 auto}
      .h{
        text-align:center;
        margin-bottom:50px;
        padding-bottom:30px;
        border-bottom:1px solid #e5e5e5
      }
      .h h1{
        font-size:2.2rem;
        font-weight:700;
        background:linear-gradient(135deg,#000 0%,#666 100%);
        -webkit-background-clip:text;
        -webkit-text-fill-color:transparent
      }
      .h p{color:#666;font-size:0.9rem}
      .h a{
        color:#1a1a1a;
        text-decoration:none;
        display:inline-block;
        margin-top:15px;
        padding:10px 20px;
        background:#fafafa;
        border:1px solid #e5e5e5;
        border-radius:8px;
        transition: all 0.2s;
      }
      .h a:hover {
        background: #f0f0f0;
        border-color: #d0d0d0;
      }
      .stats{
        display:grid;
        grid-template-columns:repeat(auto-fit,minmax(250px,1fr));
        gap:20px;
        margin-bottom:40px
      }
      .sc{
        background:#fafafa;
        border:1px solid #e5e5e5;
        border-radius:12px;
        padding:25px;
        text-align:center;
        transition: all 0.2s;
      }
      .sc:hover {
        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        transform: translateY(-2px);
      }
      .sc.danger {
        background: #fff5f5;
        border-color: #ffd4d4;
      }
      .sc.success {
        background: #f0fdf4;
        border-color: #d1fae5;
      }
      .sc.info {
        background: #f0f9ff;
        border-color: #bae6fd;
      }
      .sl{
        font-size:0.85rem;
        color:#666;
        text-transform:uppercase;
        margin-bottom:12px;
        font-weight: 600;
      }
      .sv{
        font-size:3rem;
        font-weight:700;
        color:#1a1a1a
      }
      .logs{
        background:#fafafa;
        border:1px solid #e5e5e5;
        border-radius:12px;
        padding:30px;
        max-height:700px;
        overflow-y:auto
      }
      .logs h2{
        margin-bottom:25px;
        font-size:1.2rem;
        color:#1a1a1a;
        font-weight: 600;
      }
      .le{
        background:#ffffff;
        border:1px solid #e5e5e5;
        border-left:3px solid #d0d0d0;
        padding:20px;
        margin-bottom:15px;
        border-radius:8px;
        font-size:0.85rem;
        transition: all 0.2s;
      }
      .le:hover {
        box-shadow: 0 2px 8px rgba(0,0,0,0.05);
      }
      .le.a{
        background:#fff5f5;
        border-left-color:#ff6b6b;
        border-left-width: 4px;
      }
      .le.success-log{
        background:#f0fdf4;
        border-left-color:#4ade80;
        border-left-width: 4px;
      }
      .lt{
        color:#999;
        font-size:0.75rem;
        margin-bottom:10px;
        font-family:'JetBrains Mono',monospace
      }
      .ld{margin:8px 0;color:#555}
      .b{
        display:inline-block;
        padding:4px 10px;
        border-radius:4px;
        font-size:0.7rem;
        font-weight:600;
        margin-right:8px;
        text-transform:uppercase
      }
      .b.at{
        background:#ffe4e6;
        color:#be123c;
        border: 1px solid #fecdd3;
      }
      .b.sf{
        background:#d1fae5;
        color:#065f46;
        border: 1px solid #a7f3d0;
      }
      .b.vl{
        background:#fed7aa;
        color:#9a3412;
        border:1px solid #fde68a;
      }
      code{
        background:#f5f5f5;
        padding:2px 6px;
        border-radius:4px;
        font-family:'JetBrains Mono',monospace;
        font-size:0.8rem;
        color:#1a1a1a;
        border:1px solid #e5e5e5
      }
      .rf{
        position:fixed;
        bottom:30px;
        right:30px;
        padding:14px 28px;
        background:#1a1a1a;
        color:#fff;
        border:none;
        border-radius:8px;
        cursor:pointer;
        font-weight:600;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        transition: all 0.2s;
      }
      .rf:hover {
        background: #333;
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(0,0,0,0.2);
      }
    </style>
    <meta http-equiv="refresh" content="5">
    </head><body><div class="c">
      <div class="h">
        <h1>Dashboard de Seguridad</h1>
        <p>Auto-refresh cada 5 segundos</p>
        <a href="/">← Volver</a>
      </div>
      <div class="stats">
        <div class="sc danger"><div class="sl">Ataques Detectados</div><div class="sv">${attacks.length}</div></div>
        <div class="sc success"><div class="sl">Intentos Legítimos</div><div class="sv">${legit.length}</div></div>
        <div class="sc info"><div class="sl">Total Registros</div><div class="sv">${attackLogs.length}</div></div>
      </div>
      <div class="logs">
        <h2>Registro de Actividad</h2>
        ${attackLogs.length===0?'<p style="color:#999;text-align:center;padding:40px">No hay registros aún</p>':''}
        ${attackLogs.slice().reverse().map(l=>`
          <div class="le ${l.isAttack?'a':''} ${l.result==='success' && !l.isAttack?'success-log':''}">
            <div class="lt">${l.timestamp}</div>
            <div class="ld">
              ${l.isAttack?'<span class="b at">🚨 Ataque</span>':''}
              <span class="b ${l.type==='safe'?'sf':'vl'}">${l.type==='safe'?'🛡️ Seguro':'⚠️ Vulnerable'}</span>
              <strong>Usuario:</strong> <code>${l.username}</code>
            </div>
            ${l.detectedPatterns.length>0?`<div class="ld"><strong>Patrones detectados:</strong> ${l.detectedPatterns.join(', ')}</div>`:''}
            ${l.query?`<div class="ld"><strong>Query:</strong> <code>${l.query}</code></div>`:''}
            <div class="ld"><strong>Resultado:</strong> ${l.result==='success'?'✓ Exitoso':'✗ Fallido'}</div>
          </div>
        `).join('')}
      </div>
      <button class="rf" onclick="location.reload()">Actualizar</button>
    </div></body></html>`);
});

app.get('/api/logs', (req, res) => {
  res.json({
    total: attackLogs.length,
    attacks: attackLogs.filter(l => l.isAttack).length,
    legitimate: attackLogs.filter(l => !l.isAttack).length,
    logs: attackLogs
  });
});

app.listen(port, () => {
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(' INYECCIONES SQL - DEMOSTRACION');
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`📍 http://localhost:${port}`);
  console.log(`📊 http://localhost:${port}/monitor`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n');
});
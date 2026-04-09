const express = require('express');
const session = require('express-session');
const bcrypt  = require('bcryptjs');
const helmet  = require('helmet');
const rateLimit = require('express-rate-limit');
const path    = require('path');
const fs      = require('fs');
const Database = require('better-sqlite3');

const app  = express();
const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'catalans-rutas-2024-xK9mPqZ7';
const ADMIN_PIN      = process.env.ADMIN_PIN      || '1234';

// ── DB setup ───────────────────────────────────────────────────────────────
const DB_DIR = path.join(__dirname, 'db');
if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
const db = new Database(path.join(DB_DIR, 'rutas.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    username     TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role         TEXT NOT NULL DEFAULT 'user',
    ruta_nombre  TEXT,
    color        TEXT NOT NULL DEFAULT '#185FA5',
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS productos (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre     TEXT NOT NULL,
    costo      REAL NOT NULL,
    unidad     TEXT NOT NULL DEFAULT 'unidad',
    activo     INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS clientes (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre      TEXT NOT NULL,
    ruta        TEXT NOT NULL,
    user_id     INTEGER NOT NULL,
    activo      INTEGER NOT NULL DEFAULT 1,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS ventas (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    fecha            TEXT NOT NULL,
    dia              TEXT NOT NULL,
    user_id          INTEGER NOT NULL,
    ruta_nombre      TEXT NOT NULL,
    cliente_id       INTEGER NOT NULL,
    cliente_nombre   TEXT NOT NULL,
    producto_id      INTEGER NOT NULL,
    producto_nombre  TEXT NOT NULL,
    unidad           TEXT NOT NULL,
    cantidad         REAL NOT NULL,
    precio_venta     REAL NOT NULL,
    costo            REAL NOT NULL,
    total            REAL NOT NULL,
    ganancia         REAL NOT NULL,
    created_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id)     REFERENCES users(id),
    FOREIGN KEY (cliente_id)  REFERENCES clientes(id),
    FOREIGN KEY (producto_id) REFERENCES productos(id)
  );
`);

// ── Seed users ─────────────────────────────────────────────────────────────
const seedUsers = [
  { username: 'catalans store', password: '2282007Jj',   role: 'admin', ruta_nombre: null,            color: '#854F0B' },
  { username: 'boca del monte', password: 'boca2024',    role: 'user',  ruta_nombre: 'Boca del Monte', color: '#185FA5' },
  { username: 'santa fe',       password: 'santafe2024', role: 'user',  ruta_nombre: 'Santa Fe',       color: '#3B6D11' },
];

for (const u of seedUsers) {
  const exists = db.prepare('SELECT id FROM users WHERE username = ?').get(u.username);
  if (!exists) {
    const hash = bcrypt.hashSync(u.password, 12);
    db.prepare('INSERT INTO users (username, password_hash, role, ruta_nombre, color) VALUES (?,?,?,?,?)')
      .run(u.username, hash, u.role, u.ruta_nombre, u.color);
    console.log(`✓ Usuario creado: "${u.username}"`);
  }
}

// ── Middleware ─────────────────────────────────────────────────────────────
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc:   ["'self'", "'unsafe-inline'"],
      scriptSrc:  ["'self'", "'unsafe-inline'"],
      imgSrc:     ["'self'", "data:"]
    }
  }
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const SQLiteStore = require('connect-sqlite3')(session);
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: DB_DIR }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure:   process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge:   10 * 60 * 60 * 1000
  },
  name: 'sr.sid'
}));

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { error: 'Demasiados intentos. Espera 15 minutos.' } });
const apiLimiter   = rateLimit({ windowMs: 60*1000,    max: 300, message: { error: 'Demasiadas solicitudes.' } });
app.use('/api/', apiLimiter);

function requireAuth(req, res, next) {
  if (req.session?.userId) return next();
  if (req.path.startsWith('/api/')) return res.status(401).json({ error: 'No autorizado' });
  res.redirect('/login');
}

function requireAdmin(req, res, next) {
  if (req.session?.role !== 'admin') return res.status(403).json({ error: 'Solo admin' });
  if (!req.session?.adminVerified)   return res.status(403).json({ error: 'PIN requerido' });
  next();
}

// ── Auth routes ────────────────────────────────────────────────────────────
app.get('/login', (req, res) => {
  if (req.session?.userId) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.post('/api/login', loginLimiter, (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'Credenciales requeridas' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username.trim().toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash))
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

  req.session.regenerate(err => {
    if (err) return res.status(500).json({ error: 'Error de sesión' });
    req.session.userId       = user.id;
    req.session.username     = user.username;
    req.session.role         = user.role;
    req.session.rutaNombre   = user.ruta_nombre;
    req.session.color        = user.color;
    req.session.adminVerified = false;
    res.json({ ok: true, role: user.role, rutaNombre: user.ruta_nombre, color: user.color });
  });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', requireAuth, (req, res) => {
  res.json({
    userId:    req.session.userId,
    username:  req.session.username,
    role:      req.session.role,
    rutaNombre: req.session.rutaNombre,
    color:     req.session.color
  });
});

app.post('/api/verify-pin', requireAuth, (req, res) => {
  if (req.session.role !== 'admin') return res.status(403).json({ error: 'Solo admin' });
  if (req.body.pin === ADMIN_PIN) {
    req.session.adminVerified = true;
    return res.json({ ok: true });
  }
  res.status(403).json({ error: 'PIN incorrecto' });
});

app.post('/api/close-admin', requireAuth, (req, res) => {
  req.session.adminVerified = false;
  res.json({ ok: true });
});

// ── Static & app ───────────────────────────────────────────────────────────
app.use(requireAuth);
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.get('/', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'app.html'));
});

// ── API: Productos (compartidos, cualquier usuario puede ver/editar) ───────
app.get('/api/productos', (req, res) => {
  res.json(db.prepare('SELECT * FROM productos WHERE activo=1 ORDER BY nombre').all());
});

app.post('/api/productos', (req, res) => {
  const { nombre, costo, unidad } = req.body;
  if (!nombre || costo == null) return res.status(400).json({ error: 'Datos incompletos' });
  const r = db.prepare('INSERT INTO productos (nombre,costo,unidad) VALUES (?,?,?)').run(nombre.trim(), parseFloat(costo), (unidad||'unidad').trim());
  res.json({ id: r.lastInsertRowid, nombre, costo, unidad });
});

app.put('/api/productos/:id', (req, res) => {
  const { costo, nombre, unidad } = req.body;
  db.prepare('UPDATE productos SET costo=?,nombre=?,unidad=?,updated_at=CURRENT_TIMESTAMP WHERE id=?')
    .run(parseFloat(costo), nombre, unidad, parseInt(req.params.id));
  res.json({ ok: true });
});

app.delete('/api/productos/:id', (req, res) => {
  db.prepare('UPDATE productos SET activo=0 WHERE id=?').run(parseInt(req.params.id));
  res.json({ ok: true });
});

// ── API: Clientes (filtrados por user_id para usuarios normales) ───────────
app.get('/api/clientes', (req, res) => {
  let rows;
  if (req.session.role === 'admin') {
    rows = db.prepare(`
      SELECT c.*, u.ruta_nombre, u.color
      FROM clientes c JOIN users u ON c.user_id = u.id
      WHERE c.activo=1 ORDER BY u.ruta_nombre, c.nombre
    `).all();
  } else {
    rows = db.prepare('SELECT * FROM clientes WHERE activo=1 AND user_id=? ORDER BY nombre').all(req.session.userId);
  }
  res.json(rows);
});

app.post('/api/clientes', (req, res) => {
  const { nombre, ruta } = req.body;
  if (!nombre || !ruta) return res.status(400).json({ error: 'Datos incompletos' });
  const uid = req.session.userId;
  const r = db.prepare('INSERT INTO clientes (nombre,ruta,user_id) VALUES (?,?,?)').run(nombre.trim(), ruta, uid);
  res.json({ id: r.lastInsertRowid, nombre, ruta, user_id: uid });
});

app.delete('/api/clientes/:id', (req, res) => {
  const id  = parseInt(req.params.id);
  const cli = db.prepare('SELECT user_id FROM clientes WHERE id=?').get(id);
  if (!cli) return res.status(404).json({ error: 'No encontrado' });
  if (req.session.role !== 'admin' && cli.user_id !== req.session.userId)
    return res.status(403).json({ error: 'No autorizado' });
  db.prepare('UPDATE clientes SET activo=0 WHERE id=?').run(id);
  res.json({ ok: true });
});

// ── API: Ventas ────────────────────────────────────────────────────────────
app.get('/api/ventas', (req, res) => {
  let rows;
  if (req.session.role === 'admin') {
    rows = db.prepare('SELECT * FROM ventas ORDER BY created_at DESC LIMIT 500').all();
  } else {
    rows = db.prepare('SELECT * FROM ventas WHERE user_id=? ORDER BY created_at DESC LIMIT 300').all(req.session.userId);
  }
  res.json(rows);
});

app.post('/api/ventas', (req, res) => {
  const { ventas: lista } = req.body;
  if (!Array.isArray(lista) || !lista.length) return res.status(400).json({ error: 'Sin ventas' });

  const insert = db.prepare(`
    INSERT INTO ventas (fecha,dia,user_id,ruta_nombre,cliente_id,cliente_nombre,producto_id,producto_nombre,unidad,cantidad,precio_venta,costo,total,ganancia)
    VALUES (@fecha,@dia,@user_id,@ruta_nombre,@cliente_id,@cliente_nombre,@producto_id,@producto_nombre,@unidad,@cantidad,@precio_venta,@costo,@total,@ganancia)
  `);

  const insertMany = db.transaction(items => { for (const v of items) insert.run(v); });
  insertMany(lista.map(v => ({ ...v, user_id: req.session.userId, ruta_nombre: req.session.rutaNombre || 'Sin ruta' })));
  res.json({ ok: true, count: lista.length });
});

// ── API: Ganancias — solo admin con PIN ────────────────────────────────────
app.get('/api/ganancias', requireAdmin, (req, res) => {
  const resumen = db.prepare(`
    SELECT SUM(total) as total_ventas, SUM(ganancia) as total_ganancia,
           SUM(cantidad*costo) as total_costos, COUNT(*) as total_registros FROM ventas
  `).get();

  const porRuta = db.prepare(`
    SELECT ruta_nombre, SUM(total) as ventas, SUM(ganancia) as ganancia
    FROM ventas GROUP BY ruta_nombre ORDER BY ganancia DESC
  `).all();

  const porCliente = db.prepare(`
    SELECT ruta_nombre, cliente_nombre, SUM(total) as ventas, SUM(ganancia) as ganancia
    FROM ventas GROUP BY cliente_id, cliente_nombre ORDER BY ganancia DESC
  `).all();

  const porProducto = db.prepare(`
    SELECT producto_nombre, SUM(cantidad) as unidades, SUM(ganancia) as ganancia
    FROM ventas GROUP BY producto_id, producto_nombre ORDER BY ganancia DESC
  `).all();

  const porFecha = db.prepare(`
    SELECT fecha, ruta_nombre, SUM(total) as ventas, SUM(ganancia) as ganancia
    FROM ventas GROUP BY fecha, ruta_nombre ORDER BY fecha DESC LIMIT 40
  `).all();

  res.json({ resumen, porRuta, porCliente, porProducto, porFecha });
});

// ── Start ──────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n✓ Servidor en http://localhost:${PORT}`);
  console.log('─────────────────────────────────');
  console.log('  Admin:         catalans store / 2282007Jj');
  console.log('  Boca del Monte: boca del monte / boca2024');
  console.log('  Santa Fe:       santa fe       / santafe2024');
  console.log('  PIN Admin:     ', ADMIN_PIN);
  console.log('─────────────────────────────────\n');
});

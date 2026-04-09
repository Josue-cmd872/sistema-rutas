# Sistema de Rutas — Catalans Store v2
## Dos rutas: Boca del Monte & Santa Fe

---

## Usuarios y contraseñas

| Usuario | Contraseña | Rol | Acceso |
|---------|-----------|-----|--------|
| `catalans store` | `2282007Jj` | Admin | Todo: ambas rutas + ganancias |
| `boca del monte` | `boca2024` | Usuario | Solo ruta Boca del Monte |
| `santa fe` | `santafe2024` | Usuario | Solo ruta Santa Fe |

**PIN Admin (ganancias):** `1234`

---

## Cómo funciona cada usuario

### Boca del Monte / Santa Fe (usuarios de ruta)
- Solo ven sus propios clientes
- Registran ventas de su ruta
- Ven su historial de ventas
- NO ven ganancias ni costos

### Catalans Store (Admin)
- Ve clientes y ventas de AMBAS rutas
- Accede a ganancias con PIN
- Ve comparativo por ruta: Boca del Monte vs Santa Fe
- Ve ganancia por cliente y por producto

---

## Publicar en Railway (gratis) — Paso a paso

### 1. Crear cuenta GitHub
Ve a https://github.com y crea una cuenta gratuita.

### 2. Subir archivos
- Crea un repositorio nuevo llamado `sistema-rutas`
- Sube todos los archivos de esta carpeta

### 3. Deploy en Railway
1. Ve a https://railway.app
2. "Login with GitHub"
3. "New Project" → "Deploy from GitHub repo"
4. Selecciona `sistema-rutas`
5. Railway detecta Node.js automáticamente

### 4. Variables de entorno en Railway
En tu proyecto → pestaña "Variables", agrega:
```
SESSION_SECRET=pon-aqui-una-frase-muy-larga-y-secreta
NODE_ENV=production
ADMIN_PIN=1234
PORT=3000
```

### 5. Listo
Railway te da una URL pública. Compártela con tus empleados.
Cada quien inicia sesión con su usuario y solo ve su ruta.

---

## Correr localmente (para probar)
```bash
npm install
node server.js
```
Abrir: http://localhost:3000

---

## Archivos del proyecto
```
sistema-rutas/
├── server.js         ← Servidor + API + base de datos
├── package.json      ← Dependencias Node.js
├── railway.json      ← Config de Railway
├── Procfile          ← Comando de inicio
├── .gitignore
├── README.md
├── db/               ← Se crea automáticamente
│   └── rutas.db      ← Base de datos SQLite
└── public/
    ├── login.html    ← Pantalla de login
    └── app.html      ← Aplicación principal
```

---

## Seguridad
- Contraseñas encriptadas con bcrypt (12 rounds)
- Sesiones guardadas en SQLite (no en memoria)
- Rate limiting: máx 10 intentos de login cada 15 min
- Headers de seguridad con Helmet
- Cada usuario solo puede ver/editar sus propios datos
- Ganancias y costos solo visibles para admin con PIN
- Cookies HttpOnly + SameSite strict

# ⚽ Super Campeones — Guía de Deploy

## Estructura del proyecto

```
super-campeones/
├── public/
│   ├── favicon.svg
│   └── icons/          ← íconos PWA (app instalable)
├── src/
│   ├── main.jsx        ← punto de entrada
│   └── App.jsx         ← toda la aplicación
├── index.html
├── package.json
├── vite.config.js      ← config con PWA
├── vercel.json         ← config de deploy
└── .gitignore
```

---

## 🚀 Opción 1 — Deploy en Vercel (recomendado, gratis)

### Prerequisitos
- [Node.js 18+](https://nodejs.org) instalado
- Cuenta gratuita en [vercel.com](https://vercel.com)
- [Git](https://git-scm.com) instalado

### Pasos

**1. Instalar dependencias**
```bash
cd super-campeones
npm install
```

**2. Verificar que funciona en local**
```bash
npm run dev
# Abrí http://localhost:5173
```

**3. Subir a GitHub**
```bash
git init
git add .
git commit -m "Super Campeones inicial"
```
Creá un repositorio en [github.com/new](https://github.com/new) y seguí las instrucciones para subir el código.

**4. Conectar con Vercel**
- Entrá a [vercel.com](https://vercel.com) → "Add New Project"
- Importá el repositorio de GitHub
- Vercel detecta Vite automáticamente
- Click en **Deploy**

En ~2 minutos tenés una URL pública tipo `super-campeones.vercel.app` 🎉

---

## 📱 Instalar como app en el celu

Una vez que tenés la URL de Vercel:

**Android (Chrome):**
1. Abrí la URL en Chrome
2. Tocá los 3 puntitos (menú)
3. "Agregar a pantalla de inicio"
4. Confirmá → ¡aparece como app!

**iPhone (Safari):**
1. Abrí la URL en Safari
2. Tocá el ícono de compartir (cuadrado con flecha)
3. "Agregar a pantalla de inicio"
4. Confirmá → ¡aparece como app!

---

## 💻 Opción 2 — Probar en la red local (sin internet)

```bash
npm install
npm run build
npx serve dist
```

En el celu (misma red WiFi), abrí:
```
http://[IP-de-tu-PC]:3000
```

Tu IP: ejecutá `ipconfig` (Windows) o `ifconfig` (Mac/Linux)

---

## 🔧 Opción 3 — Solo desarrollo local

```bash
npm install
npm run dev
```
Abrí `http://localhost:5173` en el navegador de tu PC.

---

## 👤 Cuentas de acceso

| Usuario  | Rol   | Descripción                        |
|----------|-------|------------------------------------|
| admin    | Admin | Puede crear torneos y cargar resultados |
| diego10  | User  | Jugador demo                       |
| leo30    | User  | Jugador demo                       |
| cr7fan   | User  | Jugador demo                       |

> Contraseña: cualquier texto (modo demo)

---

## ⚙️ Variables de entorno (opcional)

Si en el futuro agregás un backend proxy para la FIFA API, creá `.env.local`:
```
VITE_FIFA_PROXY_URL=https://tu-backend.com/api/fifa
```

---

## 📡 FIFA API — Nota importante

La app incluye integración con la API oficial de FIFA (`givevoicetofootball.fifa.com`).
Por restricciones CORS del navegador, esta integración requiere un backend proxy en producción.

Endpoints disponibles:
- `GET /api/v1/seasons/search?name=FIFA+World+Cup`
- `GET /api/v1/calendar/matches?idSeason={id}&idCompetition={id}`
- `GET /api/v1/stages?idSeason={id}&idCompetition={id}`

Documentación: https://givevoicetofootball.fifa.com/ApiFdcpSwagger

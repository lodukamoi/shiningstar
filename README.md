# Shining Star Reunion
Node.js + Express + Socket.io + Postgres. Installable web app (PWA) with push notifications, sign-up with email code confirmation,
password recovery, feed with photos/videos, likes and comments, private chat and a Chat Room with voice notes and file sharing,
voice calls and Chat Room group calls, online status and profiles.

## Environment variables (see .env.example)
Required: `DATABASE_URL`, `JWT_SECRET`.
Email codes: `BREVO_API_KEY`, `MAIL_FROM`. Media/files/voice notes: `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_UPLOAD_PRESET`.
Calls: STUN is built in; for reliability on mobile data add a TURN relay with `TURN_URLS`, `TURN_USERNAME`, `TURN_CREDENTIAL`.
Push notification keys are created automatically on first start and stored in the database.

## Run locally
    npm install
    DATABASE_URL="postgresql://..." JWT_SECRET=anything npm start     # http://localhost:3000
Notifications, installing and calls need HTTPS (localhost is allowed for testing; the deployed site has HTTPS).

## Files
server.js, icons.js (app icons), package.json, public/index.html, public/sw.js (service worker), public/manifest.json

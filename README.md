# Shining Star Reunion
Node.js + Express + Socket.io + Postgres. Sign-up with email/SMS code confirmation, password recovery, feed with photos/videos, likes and comments, live chat with online status, profiles with photos.

## Environment variables (see .env.example)
Required: `DATABASE_URL`, `JWT_SECRET`.
Email codes: `BREVO_API_KEY`, `MAIL_FROM`. Without them, codes are printed in the server console (fine for local testing only).
Media: `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_UPLOAD_PRESET` (unsigned preset). Without them, photo/video upload is disabled.
Optional SMS: `TWILIO_SID`, `TWILIO_TOKEN`, `TWILIO_FROM`. Without them, only email is offered.

## Run locally
    npm install
    DATABASE_URL="postgresql://..." JWT_SECRET=anything npm start     # http://localhost:3000
Tables are created/updated automatically on start.

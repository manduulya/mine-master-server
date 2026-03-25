// config/env.js
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'minemaster_secret_key_2024';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

module.exports = {
    PORT,
    JWT_SECRET,
    BASE_URL,
    FACEBOOK_APP_ID: process.env.FACEBOOK_APP_ID,
    FACEBOOK_APP_SECRET: process.env.FACEBOOK_APP_SECRET,
    GOOGLE_CLIENT_ID: process.env.GOOGLE_CLIENT_ID,
    GOOGLE_CLIENT_SECRET: process.env.GOOGLE_CLIENT_SECRET,
};
// server.js
const express = require('express');
const cors = require('cors');
const session = require('express-session');
const passport = require('passport');
const RedisStore = require('connect-redis').default;

const { redis } = require('./db');
const { PORT } = require('./config/env');
require('./config/passport');

const { authenticateToken } = require('./middleware/auth');
const { notFoundHandler, errorHandler } = require('./middleware/errorHandlers');

const healthRoutes = require('./routes/healthRoutes');
const flagsRoutes = require('./routes/flagsRoutes');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');
const gameRoutes = require('./routes/gameRoutes');
const leaderboardRoutes = require('./routes/leaderboardRoutes');

const app = express();

app.use(cors({ origin: true, credentials: true }));
app.use(express.json({ limit: '10mb' }));

app.use(session({
    store: new RedisStore({ client: redis, prefix: "myapp:" }),
    secret: process.env.SESSION_SECRET || 'your_session_secret',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: process.env.NODE_ENV === 'production', maxAge: 24 * 60 * 60 * 1000 },
}));

app.use(passport.initialize());
app.use(passport.session());

// Public routes
app.use(healthRoutes);
app.use(flagsRoutes);
app.use('/api/auth', authRoutes);

// Protected routes (if you want, you can apply middleware per-route instead)
app.use('/api', authenticateToken, userRoutes);
app.use('/api', authenticateToken, gameRoutes);
app.use('/api', leaderboardRoutes); // leaderboard might be public; keep as-is

app.use(notFoundHandler);
app.use(errorHandler);

app.listen(PORT, () => console.log(`🚀 Mine Master API running at http://localhost:${PORT}`));
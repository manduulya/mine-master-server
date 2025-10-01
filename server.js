// server.js
const { createClient } = require('redis');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const RedisStore = require('connect-redis').default;
const { knex: db, redis } = require('./db');


const redisClient = createClient({
    socket: {
        host: 'redis', // Use the Docker service name
        port: 6379
    }
});


redisClient.on('error', (err) => console.error('Redis Client Error', err));

async function initRedis() {
    try {
        await redisClient.connect();
        console.log('Redis connected');

        // Now it's safe to use Redis
        await redisClient.ping();
        console.log('Ping successful');
    } catch (err) {
        console.error('Redis connection failed:', err);
    }
}

initRedis();




const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'minemaster_secret_key_2024';
if (!process.env.JWT_SECRET) {
    console.warn('Warning: Using default JWT_SECRET. Set process.env.JWT_SECRET in production.');
}

// OAuth Configuration
const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID || 'your_facebook_app_id';
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET || 'your_facebook_app_secret';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'your_google_client_id';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'your_google_client_secret';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));

app.use(session({
    store: new RedisStore({
        client: redis,
        prefix: "myapp:"
    }),
    secret: process.env.SESSION_SECRET || 'your_session_secret',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

app.use(passport.initialize());
app.use(passport.session());

// Simple startup checks (non-blocking)
const MAX_RETRIES = 10;
let retries = 0;

async function connectToPostgres() {
    while (retries < MAX_RETRIES) {
        try {
            await db.raw('SELECT 1'); // or your preferred connection test
            console.log('Postgres connection OK');
            break;
        } catch (err) {
            if (err.code === '57P03') {
                console.log('Postgres is starting up, retrying...');
                retries++;
                await new Promise(res => setTimeout(res, 1000)); // wait 1 second
            } else {
                console.error('Postgres connection error', err);
                break;
            }
        }
    }
}
// db.raw('SELECT 1').then(() => console.log('Postgres connection OK')).catch(err => console.error('Postgres connection error', err));
redis.ping().then(() => console.log('Redis connection OK')).catch(err => console.error('Redis connection error', err));

// Passport serialize/deserialize using Knex
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db('users').where({ id }).first()
        .then(user => done(null, user))
        .catch(err => done(err));
});

// Passport strategies
passport.use(new FacebookStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET,
    callbackURL: `${BASE_URL}/api/auth/facebook/callback`,
    profileFields: ['id', 'emails', 'name', 'picture']
}, (accessToken, refreshToken, profile, done) => {
    try {
        const facebookId = profile.id;
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        const firstName = (profile.name && profile.name.givenName) || '';
        const lastName = (profile.name && profile.name.familyName) || '';
        const usernameBase = `${firstName}${lastName}`.toLowerCase().replace(/[^a-z0-9]/g, '') || `facebook_user_${facebookId}`;
        const profilePicture = profile.photos && profile.photos[0] ? profile.photos[0].value : null;

        // Find user by oauth provider/id
        db('users').where({ oauth_provider: 'facebook', oauth_id: facebookId }).first()
            .then(existingUser => {
                if (existingUser) return done(null, existingUser);

                // If email exists, link account
                if (email) {
                    return db('users').where({ email }).first()
                        .then(emailUser => {
                            if (emailUser) {
                                return db('users').where({ id: emailUser.id }).update({
                                    oauth_provider: 'facebook',
                                    oauth_id: facebookId,
                                    // profile_picture: profilePicture,
                                    updated_at: db.fn.now()
                                }).then(() => {
                                    return db('users').where({ id: emailUser.id }).first().then(u => done(null, u));
                                });
                            }

                            // create new user with email
                            return createOauthUser(usernameBase, email, 'facebook', facebookId, profilePicture, done);
                        });
                }

                // create new user without verified email
                return createOauthUser(usernameBase, `${usernameBase}@facebook.local`, 'facebook', facebookId, profilePicture, done);
            })
            .catch(err => done(err));
    } catch (err) {
        done(err);
    }
}));

passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/api/auth/google/callback`
}, (accessToken, refreshToken, profile, done) => {
    try {
        const googleId = profile.id;
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        const firstName = (profile.name && profile.name.givenName) || '';
        const lastName = (profile.name && profile.name.familyName) || '';
        const usernameBase = `${firstName}${lastName}`.toLowerCase().replace(/[^a-z0-9]/g, '') || `google_user_${googleId}`;
        const profilePicture = profile.photos && profile.photos[0] ? profile.photos[0].value : null;

        db('users').where({ oauth_provider: 'google', oauth_id: googleId }).first()
            .then(existingUser => {
                if (existingUser) return done(null, existingUser);

                if (email) {
                    return db('users').where({ email }).first()
                        .then(emailUser => {
                            if (emailUser) {
                                return db('users').where({ id: emailUser.id }).update({
                                    oauth_provider: 'google',
                                    oauth_id: googleId,
                                    // profile_picture: profilePicture,
                                    updated_at: db.fn.now()
                                }).then(() => db('users').where({ id: emailUser.id }).first().then(u => done(null, u)));
                            }

                            return createOauthUser(usernameBase, email, 'google', googleId, profilePicture, done);
                        });
                }

                return createOauthUser(usernameBase, `${usernameBase}@google.local`, 'google', googleId, profilePicture, done);
            })
            .catch(err => done(err));
    } catch (err) {
        done(err);
    }
}));

// Helper to create OAuth users (ensures unique username)
function createOauthUser(usernameBase, email, provider, oauthId, profilePicture, done) {
    function tryUsername(candidate, attempt = 0) {
        const testName = attempt === 0 ? candidate : `${candidate}${attempt}`;
        return db('users').where({ username: testName }).first()
            .then(existing => {
                if (existing) return tryUsername(candidate, attempt + 1);
                return db('users').insert({
                    username: testName,
                    email,
                    oauth_provider: provider,
                    oauth_id: oauthId,
                    // profile_picture: profilePicture,
                    country_flag: 'international',
                    created_at: db.fn.now(),
                    updated_at: db.fn.now()
                }).returning('id').then(rows => ({ game_id: rows[0].id || rows[0] }))
            });
    }

    return tryUsername(usernameBase);
}

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid token' });
        req.user = user;
        next();
    });
};

// Available country flags
const AVAILABLE_FLAGS = [
    'international', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'it', 'es', 'jp',
    'kr', 'cn', 'in', 'br', 'mx', 'ru', 'za', 'eg', 'ng', 'ar', 'cl', 'pe',
    'se', 'no', 'dk', 'fi', 'nl', 'be', 'ch', 'at', 'pt', 'ie', 'pl', 'cz',
    'hu', 'gr', 'tr', 'il', 'ae', 'sa', 'th', 'vn', 'id', 'my', 'sg', 'ph'
];

// --- Routes ---

// Health
app.get('/health', (req, res) => res.json({ status: 'OK', message: 'Mine Master API is running' }));

// Debug: only enabled when DEBUG=true
if (process.env.DEBUG === 'true') {
    app.get('/api/debug/tables', (req, res) => {
        const results = {};
        db.select('*').from('users').limit(500).then(users => {
            results.users = users;
            return db.select('*').from('scores').limit(500);
        }).then(scores => {
            results.scores = scores;
            return db.select('*').from('game_states').limit(500);
        }).then(game_states => {
            results.game_states = game_states;
            res.json(results);
        }).catch(err => res.status(500).json({ error: err.message }));
    });
}

// Flags
app.get('/api/flags', (req, res) => res.json({ flags: AVAILABLE_FLAGS }));

// Register
app.post('/api/auth/register', (req, res) => {
    const { username, email, password, country_flag = 'international' } = req.body;

    if (!username || !email || !password) return res.status(400).json({ error: 'Username, email, and password are required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    if (!AVAILABLE_FLAGS.includes(country_flag)) return res.status(400).json({ error: 'Invalid country flag' });

    bcrypt.hash(password, 10).then(passwordHash => {
        return db('users').insert({
            username,
            email,
            password_hash: passwordHash,
            country_flag,
            created_at: db.fn.now(),
            updated_at: db.fn.now()
        }).returning(['id', 'username', 'email']);
    }).then(rows => {
        const user = rows[0];
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.status(201).json({
            message: 'User created successfully',
            user: { id: user.id, username: user.username, email: user.email, country_flag, auth_method: 'traditional' },
            token
        });
    }).catch(err => {
        if (err && err.constraint && (err.constraint.includes('users_username_unique') || err.constraint.includes('users_email_unique'))) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }
        console.error(err);
        res.status(500).json({ error: 'Failed to create user' });
    });
});

// Login
app.post('/api/auth/login', (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });

    db('users').where({ username }).andWhere('oauth_provider', null).first()
        .then(user => {
            if (!user || !user.password_hash) return res.status(401).json({ error: 'Invalid credentials' });

            return bcrypt.compare(password, user.password_hash).then(ok => {
                if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
                const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
                res.json({
                    message: 'Login successful',
                    user: { id: user.id, username: user.username, email: user.email, country_flag: user.country_flag, auth_method: 'traditional' },
                    token
                });
            });
        }).catch(err => {
            console.error(err);
            res.status(500).json({ error: 'Server error' });
        });
});

// OAuth routes
app.get('/api/auth/facebook', passport.authenticate('facebook', { scope: ['email'] }));
app.get('/api/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    (req, res) => {
        const token = jwt.sign({ id: req.user.id, username: req.user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.redirect(`myapp://auth/success?token=${token}&user=${encodeURIComponent(JSON.stringify({
            id: req.user.id, username: req.user.username, email: req.user.email, country_flag: req.user.country_flag, auth_method: 'facebook'
        }))}`);
    }
);

app.get('/api/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/api/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        const token = jwt.sign({ id: req.user.id, username: req.user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.redirect(`myapp://auth/success?token=${token}&user=${encodeURIComponent(JSON.stringify({
            id: req.user.id, username: req.user.username, email: req.user.email, country_flag: req.user.country_flag, auth_method: 'google'
        }))}`);
    }
);

// OAuth Status check
app.get('/api/auth/oauth/status/:provider', (req, res) => {
    const { provider } = req.params;
    const { oauth_id } = req.query;
    if (!oauth_id) return res.status(400).json({ error: 'OAuth ID required' });

    db('users').where({ oauth_provider: provider, oauth_id }).first()
        .then(user => {
            if (!user) return res.status(404).json({ error: 'User not found' });
            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
            res.json({
                message: 'OAuth login successful',
                user: { id: user.id, username: user.username, email: user.email, country_flag: user.country_flag, auth_method: provider },
                token
            });
        }).catch(err => res.status(500).json({ error: 'Server error' }));
});

// Profile
app.get('/api/user/profile', authenticateToken, (req, res) => {
    db('users').where({ id: req.user.id }).select('id', 'username', 'email', 'country_flag', 'oauth_provider', 'created_at').first()
        .then(user => {
            if (!user) return res.status(404).json({ error: 'User not found' });
            res.json({ ...user, auth_method: user.oauth_provider || 'traditional' });
        }).catch(err => res.status(500).json({ error: 'Server error' }));
});

app.put('/api/user/profile', authenticateToken, (req, res) => {
    const { country_flag } = req.body;
    if (country_flag && !AVAILABLE_FLAGS.includes(country_flag)) return res.status(400).json({ error: 'Invalid country flag' });

    const updates = {};
    if (country_flag !== undefined) updates.country_flag = country_flag;
    if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No valid fields to update' });

    updates.updated_at = db.fn.now();

    db('users').where({ id: req.user.id }).update(updates)
        .then(() => res.json({ message: 'Profile updated successfully' }))
        .catch(err => res.status(500).json({ error: 'Failed to update profile' }));
});

// Start new game
app.post('/api/game/start', authenticateToken, (req, res) => {
    const { mine_count, mine_positions, level_id } = req.body;

    if (mine_count === undefined || !Array.isArray(mine_positions)) {
        return res.status(400).json({ error: 'Grid dimensions, mine count, and mine positions are required' });
    }
    if (mine_positions.length !== mine_count) {
        return res.status(400).json({ error: 'Mine positions count must match mine_count' });
    }

    // Remove any existing active game for this user
    db('game_states').where({ user_id: req.user.id, game_status: 'playing' }).del()
        .then(() => {
            return db('game_states')
                .insert({
                    user_id: req.user.id,
                    mine_count,
                    level_id,
                    mine_positions: JSON.stringify(mine_positions),
                    revealed_cells: JSON.stringify([]),
                    flagged_cells: JSON.stringify([]),
                    game_status: 'playing',
                    created_at: db.fn.now(),
                    updated_at: db.fn.now()
                })
                .returning('id');
        })
        .then(rows => {
            // rows[0] could be { id: 3 } (Postgres) or just 3 (SQLite)
            const row = rows[0];
            const gameId = typeof row === 'object' ? row.id : row;

            console.log("DEBUG: inserted rows =>", rows, "resolved gameId =>", gameId);

            res.status(201).json({
                message: 'New game started',
                game_id: gameId,
                start_time: Date.now()
            });
        })
        .catch(err => {
            console.error("ERROR inserting game state:", err);
            res.status(500).json({ error: 'Failed to create new game' });
        });
});

// Get the active game for this user
app.get('/api/game/active', authenticateToken, (req, res) => {
    db('game_states')
        .where({ user_id: req.user.id, game_status: 'playing' })
        .first()
        .then(game => {
            if (!game) return res.status(404).json({ error: 'No active game' });

            // Parse JSON fields before sending
            game.mine_positions = JSON.parse(game.mine_positions);
            game.revealed_cells = JSON.parse(game.revealed_cells);
            game.flagged_cells = JSON.parse(game.flagged_cells);

            res.json(game);
        })
        .catch(err => res.status(500).json({ error: 'Failed to fetch active game' }));
});

// Get current game
app.get('/api/game/current', authenticateToken, async (req, res) => {
    try {
        const game = await db('game_states')
            .where({ user_id: req.user.id })
            .orderBy('updated_at', 'desc')
            .first();

        if (!game) {
            return res.status(404).json({ error: 'No active game found' });
        }
        // Debug logging
        console.log('Found game:', game);
        console.log('level_id value:', game.level_id);
        console.log('level_id type:', typeof game.level_id);

        res.json({
            game_id: game.id,
            level: game.level_id,
            mine_count: game.mine_count,
            mine_positions: JSON.parse(game.mine_positions),
            revealed_cells: JSON.parse(game.revealed_cells),
            flagged_cells: JSON.parse(game.flagged_cells),
            game_status: game.game_status,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to load game state' });
    }
});



// Update game state
app.put('/api/game/update', authenticateToken, (req, res) => {
    const { game_id, revealed_cells, flagged_cells } = req.body;

    if (!game_id || !Array.isArray(revealed_cells) || !Array.isArray(flagged_cells)) {
        return res.status(400).json({ error: 'Game ID, revealed cells, and flagged cells are required' });
    }

    db('game_states')
        .where({ id: game_id, user_id: req.user.id })
        .update({
            revealed_cells: JSON.stringify(revealed_cells),
            flagged_cells: JSON.stringify(flagged_cells),
            updated_at: db.fn.now()
        })
        .then(changes => {
            if (!changes || changes === 0) return res.status(404).json({ error: 'No active game found' });
            res.json({ message: 'Game state updated successfully' });
        })
        .catch(err => {
            console.error(err);
            res.status(500).json({ error: 'Failed to update game state' });
        });
});

// Get revealed cells
app.get('/api/game/:gameId/revealed', authenticateToken, async (req, res) => {
    const { gameId } = req.params;
    const game = await db('game_states').where({ id: gameId, user_id: req.user.id }).first();
    if (!game) return res.status(404).json({ error: 'Game not found' });
    res.json({ revealed_cells: JSON.parse(game.revealed_cells) });
});

// Get flagged cells
app.get('/api/game/:gameId/flagged', authenticateToken, async (req, res) => {
    const { gameId } = req.params;
    const game = await db('game_states').where({ id: gameId, user_id: req.user.id }).first();
    if (!game) return res.status(404).json({ error: 'Game not found' });
    res.json({ flagged_cells: JSON.parse(game.flagged_cells) });
});



// Finish game (transactional)
app.post('/api/game/finish', authenticateToken, (req, res) => {
    const { won, level, score } = req.body;

    if (won === undefined || level === undefined || score === undefined) {
        return res.status(400).json({ error: 'Won status, level, and score are required' });
    }

    db.transaction(trx => {
        return trx('game_states')
            .where({ user_id: req.user.id, game_status: 'playing' })
            .first()
            .then(game => {
                if (!game) throw new Error('NO_ACTIVE_GAME');

                // Mark the game finished
                return trx('game_states')
                    .where({ id: game.id })
                    .update({
                        game_status: won ? 'won' : 'lost',
                        updated_at: db.fn.now()
                    })
                    .then(() => {
                        if (!won) return { score_id: null }; // only record score if user won

                        return trx('scores')
                            .insert({
                                user_id: req.user.id,
                                score,        // 👈 use score from request body
                                level,        // 👈 use level from request body
                                created_at: db.fn.now()
                            })
                            .returning('id')
                            .then(rows => ({ score_id: rows[0] }));
                    });
            });
    })
        .then(result => {
            res.json({
                message: 'Game finished successfully',
                won,
                score_id: result.score_id,
                score,
                level
            });
        })
        .catch(err => {
            if (err.message === 'NO_ACTIVE_GAME') {
                return res.status(404).json({ error: 'No active game found' });
            }
            console.error(err);
            res.status(500).json({ error: 'Server error' });
        });
});



// User's scores
app.get('/api/scores/user', authenticateToken, (req, res) => {
    const limit = parseInt(req.query.limit || '50');
    const offset = parseInt(req.query.offset || '0');

    db('scores')
        .select('id', 'mine_count', 'level_id', 'created_at')
        .where({ user_id: req.user.id })
        .orderBy('created_at', 'desc')
        .limit(limit)
        .offset(offset)
        .then(scores => res.json(scores))
        .catch(err => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/leaderboard', (req, res) => {
    const { level_id } = req.query;
    const limit = parseInt(req.query.limit || '10');

    let q = db('scores as s')
        .join('users as u', 's.user_id', 'u.id')
        .select('u.username', 'u.country_flag', 's.mine_count', 's.level_id', 's.created_at');

    if (level_id) q = q.where('s.level_id', level_id);

    q.orderBy('s.created_at', 'desc').limit(limit)
        .then(rows => res.json(rows))
        .catch(err => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/user/stats', authenticateToken, (req, res) => {
    const userId = req.user.id;
    db('scores')
        .where({ user_id: userId })
        .select('level', 'score', 'created_at')
        .then(stats => {
            res.json(stats); // returns an array of score objects
        })
        .catch(err => {
            console.error(err);
            res.status(500).json({ error: 'Server error' });
        });
});


// Error handling middleware
app.use((err, req, res, next) => {
    console.error('Unhandled error:', err.stack || err);
    res.status(500).json({ error: 'Something went wrong!' });
});

// 404
app.use((req, res) => res.status(404).json({ error: 'Route not found' }));

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down gracefully...');
    Promise.all([
        db.destroy().catch(err => console.error('Error closing db', err)),
        redis.quit().catch(err => console.error('Error closing redis', err))
    ]).then(() => process.exit(0));
});

// Catch-all for undefined API routes
app.use((req, res) => {
    res.status(404).json({ error: "Route not found" });
});

// Global error handler (optional but recommended)
app.use((err, req, res, next) => {
    console.error("Unhandled error:", err);
    res.status(500).json({ error: "Internal Server Error" });
});

app.listen(PORT, () => {
    console.log(`🚀 Mine Master API running at http://localhost:${PORT}`);
});

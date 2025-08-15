const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const passport = require('passport');
const FacebookStrategy = require('passport-facebook').Strategy;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'minemaster_secret_key_2024';

// OAuth Configuration
const FACEBOOK_APP_ID = process.env.FACEBOOK_APP_ID || 'your_facebook_app_id';
const FACEBOOK_APP_SECRET = process.env.FACEBOOK_APP_SECRET || 'your_facebook_app_secret';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || 'your_google_client_id';
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || 'your_google_client_secret';
const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';

// Middleware
app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json({ limit: '10mb' }));
app.use(session({
    secret: 'minemaster_session_secret',
    resave: false,
    saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());

// Initialize SQLite Database
const dbPath = path.join(__dirname, 'minemaster.db');
const db = new sqlite3.Database(dbPath);

// Create tables if they don't exist
db.serialize(() => {
    // Users table with OAuth support
    db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT,
    country_flag TEXT DEFAULT 'international',
    oauth_provider TEXT,
    oauth_id TEXT,
    profile_picture TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

    // Scores table (completed games only)
    db.run(`CREATE TABLE IF NOT EXISTS scores (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    time_seconds INTEGER NOT NULL,
    grid_width INTEGER NOT NULL,
    grid_height INTEGER NOT NULL,
    mine_count INTEGER NOT NULL,
    won BOOLEAN NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  )`);

    // Game states table (for continuing games)
    db.run(`CREATE TABLE IF NOT EXISTS game_states (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    grid_width INTEGER NOT NULL,
    grid_height INTEGER NOT NULL,
    mine_count INTEGER NOT NULL,
    mine_positions TEXT NOT NULL,
    revealed_cells TEXT NOT NULL,
    flagged_cells TEXT NOT NULL,
    game_status TEXT NOT NULL CHECK(game_status IN ('playing', 'won', 'lost')),
    start_time INTEGER NOT NULL,
    elapsed_time INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
  )`);

    // Create indexes for better performance
    db.run(`CREATE INDEX IF NOT EXISTS idx_scores_user_id ON scores (user_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_scores_time ON scores (time_seconds)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_scores_won ON scores (won)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_game_states_user_id ON game_states (user_id)`);
    db.run(`CREATE INDEX IF NOT EXISTS idx_users_oauth ON users (oauth_provider, oauth_id)`);

    // Ensure only one active game per user
    db.run(`CREATE UNIQUE INDEX IF NOT EXISTS idx_game_states_user_active ON game_states (user_id) WHERE game_status = 'playing'`);
});

// Passport configuration
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    db.get('SELECT * FROM users WHERE id = ?', [id], (err, user) => {
        done(err, user);
    });
});

// Facebook Strategy
passport.use(new FacebookStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET,
    callbackURL: `${BASE_URL}/api/auth/facebook/callback`,
    profileFields: ['id', 'emails', 'name', 'picture']
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const facebookId = profile.id;
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        const firstName = profile.name.givenName || '';
        const lastName = profile.name.familyName || '';
        const username = `${firstName}${lastName}`.toLowerCase().replace(/[^a-z0-9]/g, '') || `facebook_user_${facebookId}`;
        const profilePicture = profile.photos && profile.photos[0] ? profile.photos[0].value : null;

        // Check if user already exists with this Facebook ID
        db.get('SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?', ['facebook', facebookId], (err, existingUser) => {
            if (err) return done(err);

            if (existingUser) {
                return done(null, existingUser);
            }

            // Check if email already exists
            if (email) {
                db.get('SELECT * FROM users WHERE email = ?', [email], (err, emailUser) => {
                    if (err) return done(err);

                    if (emailUser) {
                        // Link Facebook to existing account
                        db.run('UPDATE users SET oauth_provider = ?, oauth_id = ?, profile_picture = ? WHERE id = ?',
                            ['facebook', facebookId, profilePicture, emailUser.id], (err) => {
                                if (err) return done(err);
                                return done(null, { ...emailUser, oauth_provider: 'facebook', oauth_id: facebookId, profile_picture: profilePicture });
                            });
                    } else {
                        // Create new user
                        createOAuthUser(username, email, 'facebook', facebookId, profilePicture, done);
                    }
                });
            } else {
                // Create new user without email
                createOAuthUser(username, `${username}@facebook.local`, 'facebook', facebookId, profilePicture, done);
            }
        });
    } catch (error) {
        done(error);
    }
}));

// Google Strategy
passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/api/auth/google/callback`
}, async (accessToken, refreshToken, profile, done) => {
    try {
        const googleId = profile.id;
        const email = profile.emails && profile.emails[0] ? profile.emails[0].value : null;
        const firstName = profile.name.givenName || '';
        const lastName = profile.name.familyName || '';
        const username = `${firstName}${lastName}`.toLowerCase().replace(/[^a-z0-9]/g, '') || `google_user_${googleId}`;
        const profilePicture = profile.photos && profile.photos[0] ? profile.photos[0].value : null;

        // Check if user already exists with this Google ID
        db.get('SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?', ['google', googleId], (err, existingUser) => {
            if (err) return done(err);

            if (existingUser) {
                return done(null, existingUser);
            }

            // Check if email already exists
            if (email) {
                db.get('SELECT * FROM users WHERE email = ?', [email], (err, emailUser) => {
                    if (err) return done(err);

                    if (emailUser) {
                        // Link Google to existing account
                        db.run('UPDATE users SET oauth_provider = ?, oauth_id = ?, profile_picture = ? WHERE id = ?',
                            ['google', googleId, profilePicture, emailUser.id], (err) => {
                                if (err) return done(err);
                                return done(null, { ...emailUser, oauth_provider: 'google', oauth_id: googleId, profile_picture: profilePicture });
                            });
                    } else {
                        // Create new user
                        createOAuthUser(username, email, 'google', googleId, profilePicture, done);
                    }
                });
            } else {
                // Create new user without email
                createOAuthUser(username, `${username}@google.local`, 'google', googleId, profilePicture, done);
            }
        });
    } catch (error) {
        done(error);
    }
}));

// Helper function to create OAuth user
function createOAuthUser(username, email, provider, oauthId, profilePicture, done) {
    // Ensure username is unique
    const checkUsername = (baseUsername, attempt = 0) => {
        const testUsername = attempt === 0 ? baseUsername : `${baseUsername}${attempt}`;

        db.get('SELECT * FROM users WHERE username = ?', [testUsername], (err, existingUser) => {
            if (err) return done(err);

            if (existingUser) {
                checkUsername(baseUsername, attempt + 1);
            } else {
                // Create user
                db.run('INSERT INTO users (username, email, oauth_provider, oauth_id, profile_picture) VALUES (?, ?, ?, ?, ?)',
                    [testUsername, email, provider, oauthId, profilePicture], function (err) {
                        if (err) return done(err);

                        const newUser = {
                            id: this.lastID,
                            username: testUsername,
                            email,
                            oauth_provider: provider,
                            oauth_id: oauthId,
                            profile_picture: profilePicture,
                            country_flag: 'international'
                        };
                        done(null, newUser);
                    });
            }
        });
    };

    checkUsername(username);
}

// JWT Authentication middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'Invalid token' });
        }
        req.user = user;
        next();
    });
};

// Available country flags (ISO 3166-1 alpha-2 codes)
const AVAILABLE_FLAGS = [
    'international', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'it', 'es', 'jp',
    'kr', 'cn', 'in', 'br', 'mx', 'ru', 'za', 'eg', 'ng', 'ar', 'cl', 'pe',
    'se', 'no', 'dk', 'fi', 'nl', 'be', 'ch', 'at', 'pt', 'ie', 'pl', 'cz',
    'hu', 'gr', 'tr', 'il', 'ae', 'sa', 'th', 'vn', 'id', 'my', 'sg', 'ph'
];

// Routes

// Health check
app.get('/health', (req, res) => {
    res.json({ status: 'OK', message: 'Mine Master API is running' });
});

// Debug endpoint - remove in production
app.get('/api/debug/tables', (req, res) => {
    const results = {};

    db.all('SELECT * FROM users', [], (err, users) => {
        if (err) return res.status(500).json({ error: err.message });
        results.users = users;

        db.all('SELECT * FROM scores', [], (err, scores) => {
            if (err) return res.status(500).json({ error: err.message });
            results.scores = scores;

            db.all('SELECT * FROM game_states', [], (err, gameStates) => {
                if (err) return res.status(500).json({ error: err.message });
                results.game_states = gameStates;

                res.json(results);
            });
        });
    });
});

// Get available country flags
app.get('/api/flags', (req, res) => {
    res.json({ flags: AVAILABLE_FLAGS });
});

// User Registration (Traditional)
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password, country_flag = 'international' } = req.body;

        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }

        if (password.length < 6) {
            return res.status(400).json({ error: 'Password must be at least 6 characters long' });
        }

        if (!AVAILABLE_FLAGS.includes(country_flag)) {
            return res.status(400).json({ error: 'Invalid country flag' });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        db.run(
            'INSERT INTO users (username, email, password_hash, country_flag) VALUES (?, ?, ?, ?)',
            [username, email, passwordHash, country_flag],
            function (err) {
                if (err) {
                    if (err.message.includes('UNIQUE constraint failed')) {
                        return res.status(409).json({ error: 'Username or email already exists' });
                    }
                    return res.status(500).json({ error: 'Failed to create user' });
                }

                const token = jwt.sign({ id: this.lastID, username }, JWT_SECRET, { expiresIn: '24h' });
                res.status(201).json({
                    message: 'User created successfully',
                    user: {
                        id: this.lastID,
                        username,
                        email,
                        country_flag,
                        auth_method: 'traditional'
                    },
                    token
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// User Login (Traditional)
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        db.get(
            'SELECT * FROM users WHERE username = ? AND oauth_provider IS NULL',
            [username],
            async (err, user) => {
                if (err) {
                    return res.status(500).json({ error: 'Server error' });
                }

                if (!user || !user.password_hash || !await bcrypt.compare(password, user.password_hash)) {
                    return res.status(401).json({ error: 'Invalid credentials' });
                }

                const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
                res.json({
                    message: 'Login successful',
                    user: {
                        id: user.id,
                        username: user.username,
                        email: user.email,
                        country_flag: user.country_flag,
                        profile_picture: user.profile_picture,
                        auth_method: 'traditional'
                    },
                    token
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Facebook OAuth Routes
app.get('/api/auth/facebook',
    passport.authenticate('facebook', { scope: ['email'] })
);

app.get('/api/auth/facebook/callback',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    (req, res) => {
        // Generate JWT token
        const token = jwt.sign({ id: req.user.id, username: req.user.username }, JWT_SECRET, { expiresIn: '24h' });

        // Redirect to your Flutter app with token
        res.redirect(`myapp://auth/success?token=${token}&user=${encodeURIComponent(JSON.stringify({
            id: req.user.id,
            username: req.user.username,
            email: req.user.email,
            country_flag: req.user.country_flag,
            profile_picture: req.user.profile_picture,
            auth_method: 'facebook'
        }))}`);
    }
);

// Google OAuth Routes
app.get('/api/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

app.get('/api/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    (req, res) => {
        // Generate JWT token
        const token = jwt.sign({ id: req.user.id, username: req.user.username }, JWT_SECRET, { expiresIn: '24h' });

        // Redirect to your Flutter app with token
        res.redirect(`myapp://auth/success?token=${token}&user=${encodeURIComponent(JSON.stringify({
            id: req.user.id,
            username: req.user.username,
            email: req.user.email,
            country_flag: req.user.country_flag,
            profile_picture: req.user.profile_picture,
            auth_method: 'google'
        }))}`);
    }
);

// OAuth Status Check (for mobile apps)
app.get('/api/auth/oauth/status/:provider', (req, res) => {
    const { provider } = req.params;
    const { oauth_id } = req.query;

    if (!oauth_id) {
        return res.status(400).json({ error: 'OAuth ID required' });
    }

    db.get('SELECT * FROM users WHERE oauth_provider = ? AND oauth_id = ?', [provider, oauth_id], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Server error' });
        }

        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
        res.json({
            message: 'OAuth login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                country_flag: user.country_flag,
                profile_picture: user.profile_picture,
                auth_method: provider
            },
            token
        });
    });
});

// Get User Profile
app.get('/api/user/profile', authenticateToken, (req, res) => {
    db.get(
        'SELECT id, username, email, country_flag, oauth_provider, profile_picture, created_at FROM users WHERE id = ?',
        [req.user.id],
        (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Server error' });
            }
            if (!user) {
                return res.status(404).json({ error: 'User not found' });
            }
            res.json({
                ...user,
                auth_method: user.oauth_provider || 'traditional'
            });
        }
    );
});

// Update User Profile
app.put('/api/user/profile', authenticateToken, (req, res) => {
    const { country_flag } = req.body;

    if (country_flag && !AVAILABLE_FLAGS.includes(country_flag)) {
        return res.status(400).json({ error: 'Invalid country flag' });
    }

    const updates = [];
    const params = [];

    if (country_flag !== undefined) {
        updates.push('country_flag = ?');
        params.push(country_flag);
    }

    if (updates.length === 0) {
        return res.status(400).json({ error: 'No valid fields to update' });
    }

    updates.push('updated_at = CURRENT_TIMESTAMP');
    params.push(req.user.id);

    const query = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;

    db.run(query, params, function (err) {
        if (err) {
            return res.status(500).json({ error: 'Failed to update profile' });
        }

        res.json({ message: 'Profile updated successfully' });
    });
});

// Start New Game
app.post('/api/game/start', authenticateToken, (req, res) => {
    try {
        const { grid_width, grid_height, mine_count, mine_positions } = req.body;

        if (!grid_width || !grid_height || mine_count === undefined || !mine_positions) {
            return res.status(400).json({ error: 'Grid dimensions, mine count, and mine positions are required' });
        }

        if (mine_positions.length !== mine_count) {
            return res.status(400).json({ error: 'Mine positions count must match mine_count' });
        }

        // Delete any existing active game for this user
        db.run('DELETE FROM game_states WHERE user_id = ? AND game_status = ?', [req.user.id, 'playing'], (err) => {
            if (err) {
                return res.status(500).json({ error: 'Failed to clear previous game' });
            }

            // Create new game state
            const startTime = Date.now();
            db.run(
                `INSERT INTO game_states (user_id, grid_width, grid_height, mine_count, mine_positions, 
         revealed_cells, flagged_cells, game_status, start_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [req.user.id, grid_width, grid_height, mine_count, JSON.stringify(mine_positions),
                JSON.stringify([]), JSON.stringify([]), 'playing', startTime],
                function (err) {
                    if (err) {
                        return res.status(500).json({ error: 'Failed to create new game' });
                    }

                    res.status(201).json({
                        message: 'New game started',
                        game_id: this.lastID,
                        start_time: startTime
                    });
                }
            );
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get Current Game State
app.get('/api/game/current', authenticateToken, (req, res) => {
    db.get(
        'SELECT * FROM game_states WHERE user_id = ? AND game_status = ?',
        [req.user.id, 'playing'],
        (err, game) => {
            if (err) {
                return res.status(500).json({ error: 'Server error' });
            }

            if (!game) {
                return res.json({ game: null });
            }

            res.json({
                game: {
                    id: game.id,
                    grid_width: game.grid_width,
                    grid_height: game.grid_height,
                    mine_count: game.mine_count,
                    mine_positions: JSON.parse(game.mine_positions),
                    revealed_cells: JSON.parse(game.revealed_cells),
                    flagged_cells: JSON.parse(game.flagged_cells),
                    game_status: game.game_status,
                    start_time: game.start_time,
                    elapsed_time: game.elapsed_time
                }
            });
        }
    );
});

// Update Game State
app.put('/api/game/update', authenticateToken, (req, res) => {
    try {
        const { revealed_cells, flagged_cells, elapsed_time } = req.body;

        if (!revealed_cells || !flagged_cells || elapsed_time === undefined) {
            return res.status(400).json({ error: 'Revealed cells, flagged cells, and elapsed time are required' });
        }

        db.run(
            `UPDATE game_states SET revealed_cells = ?, flagged_cells = ?, elapsed_time = ?, updated_at = CURRENT_TIMESTAMP 
       WHERE user_id = ? AND game_status = ?`,
            [JSON.stringify(revealed_cells), JSON.stringify(flagged_cells), elapsed_time, req.user.id, 'playing'],
            function (err) {
                if (err) {
                    return res.status(500).json({ error: 'Failed to update game state' });
                }

                if (this.changes === 0) {
                    return res.status(404).json({ error: 'No active game found' });
                }

                res.json({ message: 'Game state updated successfully' });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Finish Game (Win or Loss)
app.post('/api/game/finish', authenticateToken, (req, res) => {
    try {
        const { won, final_time } = req.body;

        if (won === undefined || final_time === undefined) {
            return res.status(400).json({ error: 'Won status and final time are required' });
        }

        // Get current game
        db.get(
            'SELECT * FROM game_states WHERE user_id = ? AND game_status = ?',
            [req.user.id, 'playing'],
            (err, game) => {
                if (err) {
                    return res.status(500).json({ error: 'Server error' });
                }

                if (!game) {
                    return res.status(404).json({ error: 'No active game found' });
                }

                // Start transaction
                db.serialize(() => {
                    db.run('BEGIN TRANSACTION');

                    // Update game state to finished
                    const newStatus = won ? 'won' : 'lost';
                    db.run(
                        'UPDATE game_states SET game_status = ?, elapsed_time = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
                        [newStatus, final_time, game.id],
                        function (err) {
                            if (err) {
                                db.run('ROLLBACK');
                                return res.status(500).json({ error: 'Failed to update game state' });
                            }

                            // Save score to scores table
                            db.run(
                                'INSERT INTO scores (user_id, time_seconds, grid_width, grid_height, mine_count, won) VALUES (?, ?, ?, ?, ?, ?)',
                                [req.user.id, Math.floor(final_time / 1000), game.grid_width, game.grid_height, game.mine_count, won],
                                function (err) {
                                    if (err) {
                                        db.run('ROLLBACK');
                                        return res.status(500).json({ error: 'Failed to save score' });
                                    }

                                    db.run('COMMIT');
                                    res.json({
                                        message: 'Game finished successfully',
                                        score_id: this.lastID,
                                        won,
                                        time_seconds: Math.floor(final_time / 1000)
                                    });
                                }
                            );
                        }
                    );
                });
            }
        );
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

// Get User's Scores
app.get('/api/scores/user', authenticateToken, (req, res) => {
    const { limit = 50, offset = 0 } = req.query;

    const query = `
    SELECT id, time_seconds, grid_width, grid_height, mine_count, won, created_at 
    FROM scores 
    WHERE user_id = ?
    ORDER BY created_at DESC 
    LIMIT ? OFFSET ?
  `;

    db.all(query, [req.user.id, parseInt(limit), parseInt(offset)], (err, scores) => {
        if (err) {
            return res.status(500).json({ error: 'Server error' });
        }
        res.json(scores);
    });
});

// Get User's Best Scores
app.get('/api/scores/user/best', authenticateToken, (req, res) => {
    const query = `
    SELECT 
      grid_width,
      grid_height,
      mine_count,
      MIN(time_seconds) as best_time,
      COUNT(*) as games_played,
      SUM(CASE WHEN won = 1 THEN 1 ELSE 0 END) as games_won
    FROM scores 
    WHERE user_id = ?
    GROUP BY grid_width, grid_height, mine_count
    ORDER BY mine_count ASC, grid_width ASC, grid_height ASC
  `;

    db.all(query, [req.user.id], (err, bestScores) => {
        if (err) {
            return res.status(500).json({ error: 'Server error' });
        }

        const scoresWithPercentage = bestScores.map(score => ({
            ...score,
            win_percentage: score.games_played > 0 ? Math.round((score.games_won / score.games_played) * 100) : 0
        }));

        res.json(scoresWithPercentage);
    });
});

// Get Global Leaderboard
app.get('/api/leaderboard', (req, res) => {
    const { grid_width, grid_height, mine_count, limit = 10 } = req.query;

    let query = `
    SELECT u.username, u.country_flag, s.time_seconds, s.grid_width, s.grid_height, s.mine_count, s.created_at
    FROM scores s
    JOIN users u ON s.user_id = u.id
    WHERE s.won = 1
  `;

    const params = [];

    if (grid_width && grid_height && mine_count) {
        query += ' AND s.grid_width = ? AND s.grid_height = ? AND s.mine_count = ?';
        params.push(parseInt(grid_width), parseInt(grid_height), parseInt(mine_count));
    }

    query += ' ORDER BY s.time_seconds ASC LIMIT ?';
    params.push(parseInt(limit));

    db.all(query, params, (err, leaderboard) => {
        if (err) {
            return res.status(500).json({ error: 'Server error' });
        }
        res.json(leaderboard);
    });
});

// Get User Statistics
app.get('/api/stats/user', authenticateToken, (req, res) => {
    const statsQuery = `
    SELECT 
      COUNT(*) as total_games,
      SUM(CASE WHEN won = 1 THEN 1 ELSE 0 END) as games_won,
      ROUND(AVG(CASE WHEN won = 1 THEN time_seconds END), 2) as avg_win_time,
      MIN(CASE WHEN won = 1 THEN time_seconds END) as best_time,
      MAX(CASE WHEN won = 1 THEN time_seconds END) as worst_win_time,
      AVG(grid_width * grid_height) as avg_grid_size,
      AVG(mine_count) as avg_mine_count
    FROM scores 
    WHERE user_id = ?
  `;

    db.get(statsQuery, [req.user.id], (err, stats) => {
        if (err) {
            return res.status(500).json({ error: 'Server error' });
        }

        const winPercentage = stats.total_games > 0 ? Math.round((stats.games_won / stats.total_games) * 100) : 0;

        res.json({
            ...stats,
            win_percentage: winPercentage
        });
    });
});

// Error handling middleware and need more error handing
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({ error: 'Something went wrong!' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Start server
app.listen(PORT, () => {
    console.log(`Mine Master API server running on port ${PORT}`);
});

// Graceful shutdown
process.on('SIGINT', () => {
    console.log('\nShutting down gracefully...');
    db.close((err) => {
        if (err) {
            console.error('Error closing database:', err.message);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});
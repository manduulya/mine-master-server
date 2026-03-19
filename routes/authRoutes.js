// routes/authRoutes.js
const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { knex: db } = require('../db');
const { JWT_SECRET } = require('../config/env');
const { safeStringify } = require('../utils/safeStringify');
const { AVAILABLE_FLAGS } = require('../config/constants');

const router = express.Router();

// /api/auth/register
router.post('/register', async (req, res) => {
    const { username, email, password, country_flag = 'international' } = req.body;

    const normalizedUsername = username?.trim().toLowerCase();
    const normalizedEmail = email?.trim().toLowerCase();

    if (!normalizedUsername || !normalizedEmail || !password) return res.status(400).json({ error: 'Username, email, and password are required' });
    if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    if (!AVAILABLE_FLAGS.includes(country_flag)) return res.status(400).json({ error: 'Invalid country flag' });

    bcrypt.hash(password, 10).then(passwordHash => {
        return db('users').insert({
            username: normalizedUsername,
            email: normalizedEmail,
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

// /api/auth/login
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const normalizedUsername = username?.trim().toLowerCase();
    if (!normalizedUsername || !password) return res.status(400).json({ error: 'Username and password are required' });

    db('users').where({ username: normalizedUsername }).andWhere('oauth_provider', null).first()
        .then(user => {
            if (!user) {
                return res.status(404).json({ error: 'Account not found' });
            }

            if (!user.password_hash) {
                return res.status(401).json({ error: 'Invalid credentials' });
            }

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

// /api/auth/reset-password
router.post('/reset-password', async (req, res) => {
    const { username, email, new_password } = req.body;

    console.log('=== PASSWORD RESET REQUEST ===');
    console.log('Raw body:', req.body);
    console.log('Username received:', username);
    console.log('Email received:', email);
    console.log('Password length:', new_password ? new_password.length : 0);

    // Validation
    if (!username || !email || !new_password) {
        console.log('❌ Validation failed: Missing fields');
        return res.status(400).json({ error: 'Username, email, and new password are required' });
    }

    if (new_password.length < 6) {
        console.log('❌ Validation failed: Password too short');
        return res.status(400).json({ error: 'Password must be at least 6 characters long' });
    }

    const trimmedUsername = username.trim().toLowerCase();
    const trimmedEmail = email.trim().toLowerCase();

    console.log('After trimming:');
    console.log('  Username:', `"${trimmedUsername}"`);
    console.log('  Email:', `"${trimmedEmail}"`);

    // Find user by username AND email (both must match for security)
    db('users')
        .where({ username: trimmedUsername, email: trimmedEmail })
        .first()
        .then(user => {
            console.log('Database query result:', user ? 'User found' : 'No user found');

            if (user) {
                console.log('Found user:', {
                    id: user.id,
                    username: user.username,
                    email: user.email
                });
            } else {
                console.log('❌ No matching user in database');
                console.log('Searching for all users with this username:');

                // Debug: Check if username exists at all
                return db('users')
                    .where({ username: trimmedUsername })
                    .first()
                    .then(userByUsername => {
                        if (userByUsername) {
                            console.log('Found user by username only:', {
                                username: userByUsername.username,
                                email: userByUsername.email
                            });
                            console.log('⚠️ Username exists but email does not match!');
                            console.log(`  Provided email: "${trimmedEmail}"`);
                            console.log(`  Actual email: "${userByUsername.email}"`);
                        } else {
                            console.log('❌ Username does not exist in database at all');
                        }

                        return res.status(404).json({
                            error: 'No account found with this username and email'
                        });
                    });
            }

            // Hash the new password
            return bcrypt.hash(new_password, 10).then(passwordHash => {
                console.log('✅ Password hashed successfully');

                // Update the password in the database
                return db('users')
                    .where({ id: user.id })
                    .update({
                        password_hash: passwordHash,
                        updated_at: db.fn.now()
                    })
                    .then(() => {
                        console.log('✅ Password updated successfully for user:', user.username);
                        res.json({
                            message: 'Password reset successfully',
                            success: true
                        });
                    });
            });
        })
        .catch(err => {
            console.error('❌ Password reset error:', err);
            res.status(500).json({ error: 'Failed to reset password' });
        });
});

// /api/auth/facebook
router.post('/facebook', async (req, res) => {
    console.log('\n=== FACEBOOK AUTH REQUEST START ===');
    console.log('📩 Request received at:', new Date().toISOString());
    console.log('📩 Headers:', safeStringify(req.headers, null, 2));
    console.log('📩 Body:', safeStringify(req.body, null, 2));

    const { facebook_id, name, email } = req.body;

    console.log('📝 Extracted values:');
    console.log('  - Facebook ID:', facebook_id, '(type:', typeof facebook_id, ')');
    console.log('  - Name:', name, '(type:', typeof name, ')');
    console.log('  - Email:', email, '(type:', typeof email, ')');

    // Validation
    if (!facebook_id || !name) {
        console.log('❌ Validation failed: Missing required fields');
        return res.status(400).json({ error: 'Facebook ID and name are required' });
    }

    try {
        // --------------------------------------------------
        // 1) EXISTING USER BY OAUTH
        // --------------------------------------------------
        console.log('🔍 Searching for existing Facebook user by oauth...');
        let user = await db('users')
            .where({ oauth_provider: 'facebook', oauth_id: facebook_id })
            .first();

        console.log('📊 OAuth query result:', user ? 'User FOUND' : 'User NOT FOUND');

        // --------------------------------------------------
        // 2) IF NOT FOUND, TRY LINK BY EMAIL (IF PROVIDED)
        //    (handles case where user signed up with email/password before)
        // --------------------------------------------------
        if (!user && email) {
            console.log('🔗 Trying to link existing account by email:', email);

            const emailUser = await db('users').where({ email }).first();

            if (emailUser) {
                console.log('✅ Found existing user by email. Linking Facebook oauth to this user:', {
                    id: emailUser.id,
                    username: emailUser.username,
                    email: emailUser.email,
                });

                await db('users')
                    .where({ id: emailUser.id })
                    .update({
                        oauth_provider: 'facebook',
                        oauth_id: facebook_id,
                        updated_at: db.fn.now(),
                    });

                user = await db('users')
                    .select('id', 'username', 'email', 'country_flag')
                    .where({ id: emailUser.id })
                    .first();
            } else {
                console.log('ℹ️ No existing user found by email to link.');
            }
        }

        // --------------------------------------------------
        // 3) IF STILL NOT FOUND, CREATE NEW USER
        // --------------------------------------------------
        if (!user) {
            console.log('🆕 New Facebook user — creating account...');

            const firstName = String(name || '')
                .trim()
                .toLowerCase()
                .split(/\s+/)[0] || 'user';

            const baseUsername = firstName
                .toLowerCase()
                .replace(/[^a-z0-9]/g, '') || 'user';

            // Try a few times to avoid username collisions
            let createdUser = null;


            for (let attempt = 0; attempt < 5; attempt++) {
                const username = attempt === 0
                    ? baseUsername
                    : `${baseUsername}${Math.floor(1000 + Math.random() * 9000)}`; // 4-digit suffix

                const newUser = {
                    username,
                    email: email || `${facebook_id}@facebook.temp`,
                    oauth_provider: 'facebook',
                    oauth_id: facebook_id,
                    country_flag: 'international',
                    created_at: db.fn.now(),
                    updated_at: db.fn.now(),
                };

                try {
                    const rows = await db('users').insert(newUser).returning('id');
                    const insertedId =
                        Array.isArray(rows) && rows.length
                            ? (typeof rows[0] === 'object' ? rows[0].id : rows[0])
                            : null;

                    createdUser = await db('users')
                        .select('id', 'username', 'email', 'country_flag')
                        .where({ id: insertedId })
                        .first();

                    if (createdUser) break;
                } catch (e) {
                    const msg = (e && e.message) ? e.message : String(e);
                    const isUniqueViolation =
                        msg.toLowerCase().includes('unique') ||
                        msg.toLowerCase().includes('duplicate') ||
                        msg.toLowerCase().includes('constraint');

                    // If username taken, retry with suffix
                    if (!isUniqueViolation || attempt === 4) throw e;
                }
            }

            if (!createdUser) {
                throw new Error('Failed to create user after multiple attempts');
            }

            user = createdUser;

            console.log('✅ New user created:', user);

            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
                expiresIn: '24h',
            });

            const response = {
                message: 'User created successfully via Facebook',
                user: {
                    id: user.id,
                    username: user.username,
                    email: user.email,
                    country_flag: user.country_flag,
                    auth_provider: 'facebook',
                },
                token,
            };

            console.log('📤 Sending response (201):', safeStringify(response, null, 2));
            console.log('=== FACEBOOK AUTH REQUEST END (NEW USER) ===\n');

            return res.status(201).json(response);
        }

        // --------------------------------------------------
        // 4) EXISTING (OR LINKED) USER LOGIN
        // --------------------------------------------------
        console.log('👤 Existing/Linked user details:', {
            id: user.id,
            username: user.username,
            email: user.email,
        });

        await db('users').where({ id: user.id }).update({ updated_at: db.fn.now() });

        console.log('🔑 Generating JWT token...');

        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, {
            expiresIn: '24h',
        });

        const response = {
            message: 'Login successful',
            user: {
                id: user.id,
                username: user.username,
                email: user.email,
                country_flag: user.country_flag,
                auth_provider: 'facebook',
            },
            token,
        };

        console.log('📤 Sending response:', safeStringify(response, null, 2));
        console.log('=== FACEBOOK AUTH REQUEST END (SUCCESS) ===\n');

        return res.json(response);
    } catch (err) {
        // Safer logging (avoid circular JSON problems)
        console.error('❌ FACEBOOK AUTH ERROR:', {
            message: err?.message,
            stack: err?.stack,
        });
        console.log('=== FACEBOOK AUTH REQUEST END (ERROR) ===\n');

        return res.status(500).json({
            error: 'Failed to authenticate with Facebook',
            details: err?.message || 'Unknown error',
        });
    }
});


router.get('/oauth/status/:provider', (req, res) => {

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

module.exports = router;
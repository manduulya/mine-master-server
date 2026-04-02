// routes/userRoutes.js
const express = require('express');
const bcrypt = require('bcrypt');
const { knex: db } = require('../db');
const { authenticateToken } = require('../middleware/auth');
const { AVAILABLE_FLAGS } = require('../config/constants');



const router = express.Router();

router.get('/user/stats', authenticateToken, async (req, res) => {
    try {
        const gamesPlayed = await db('game_states')
            .where({ user_id: req.user.id })
            .whereIn('game_status', ['won', 'lost'])
            .count('* as count')
            .first();

        const gamesWon = await db('game_states')
            .where({ user_id: req.user.id, game_status: 'won' })
            .count('* as count')
            .first();

        const totalScore = await db('scores')
            .where({ user_id: req.user.id })
            .sum('score as total')
            .first();

        // Get hints and streak from the most recent finished game
        const lastGame = await db('game_states')
            .where({ user_id: req.user.id })
            .whereIn('game_status', ['won', 'lost'])
            .orderBy('updated_at', 'desc')
            .select('hints', 'streak')
            .first();

        const played = parseInt(gamesPlayed?.count || '0');
        const won = parseInt(gamesWon?.count || '0');
        const total = parseInt(totalScore?.total || '0');

        res.json({
            games_played: played,
            games_won: won,
            total_score: total,
            hints: lastGame?.hints ?? 3,
            streak: lastGame?.streak || 0,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to load stats' });
    }
});




router.get('/user/score', authenticateToken, async (req, res) => {
    db('scores')
        .where({ user_id: req.user.id })
        .first()
        .then(score => {
            if (!score) {
                return res.json({ score: 0, level: 0 });
            }
            res.json({
                score: score.score || 0,
                level: score.level || 0
            });
        })
        .catch(err => {
            console.error(err);
            res.status(500).json({ error: 'Server error' });
        });
});

router.put('/user/profile', authenticateToken, async (req, res) => {

    const { country_flag, username, current_password, new_password } = req.body;
    console.log('📥 Profile update request:', {
        user_id: req.user.id,
        body: req.body
    });

    try {
        const updates = {};

        // Country flag update
        if (country_flag !== undefined) {
            if (!AVAILABLE_FLAGS.includes(country_flag)) {
                return res.status(400).json({ error: 'Invalid country flag' });
            }
            updates.country_flag = country_flag;
        }

        // Username update
        if (username !== undefined) {
            if (!username || username.trim().length === 0) {
                return res.status(400).json({ error: 'Username cannot be empty' });
            }

            // Check if username is already taken by another user (case-insensitive)
            const existing = await db('users')
                .whereRaw('LOWER(username) = ?', [username.trim().toLowerCase()])
                .whereNot({ id: req.user.id })
                .first();

            if (existing) {
                return res.status(409).json({ error: 'Username already taken' });
            }
            updates.username = username.trim();
        }

        // Password update (requires current password verification)
        if (new_password !== undefined) {
            if (!current_password) {
                return res.status(400).json({ error: 'Current password required to change password' });
            }

            const user = await db('users').where({ id: req.user.id }).first();

            // Check if user has OAuth login (no password set)
            if (user.oauth_provider) {
                return res.status(400).json({
                    error: 'Cannot set password for OAuth accounts'
                });
            }

            if (!user.password_hash) {
                return res.status(400).json({
                    error: 'No password set for this account'
                });
            }

            // Verify current password
            const validPassword = await bcrypt.compare(current_password, user.password_hash);
            if (!validPassword) {
                return res.status(401).json({ error: 'Current password is incorrect' });
            }

            if (new_password.length < 6) {
                return res.status(400).json({
                    error: 'New password must be at least 6 characters'
                });
            }

            updates.password_hash = await bcrypt.hash(new_password, 10);
        }

        if (Object.keys(updates).length === 0) {
            return res.status(400).json({ error: 'No valid fields to update' });
        }

        updates.updated_at = db.fn.now();

        await db('users').where({ id: req.user.id }).update(updates);

        // Get updated user info to return
        const updatedUser = await db('users')
            .where({ id: req.user.id })
            .select('id', 'username', 'email', 'country_flag')
            .first();

        res.json({
            message: 'Profile updated successfully',
            user: updatedUser,
            updated_fields: Object.keys(updates).filter(key => key !== 'updated_at' && key !== 'password_hash')
        });
    } catch (err) {
        console.error('Profile update error:', err);
        res.status(500).json({ error: 'Failed to update profile' });
    }
});

router.get('/user/profile', authenticateToken, async (req, res) => {
    db('users').where({ id: req.user.id }).select('id', 'username', 'email', 'country_flag', 'oauth_provider', 'created_at').first()
        .then(user => {
            if (!user) return res.status(404).json({ error: 'User not found' });
            res.json({ ...user, auth_method: user.oauth_provider || 'traditional' });
        }).catch(err => res.status(500).json({ error: 'Server error' }));
});

router.delete('/user/profile', authenticateToken, async (req, res) => {
    try {
        const deleted = await db('users').where({ id: req.user.id }).delete();
        if (!deleted) {
            return res.status(404).json({ error: 'User not found' });
        }
        res.json({ message: 'Account deleted successfully' });
    } catch (err) {
        console.error('Account deletion error:', err);
        res.status(500).json({ error: 'Failed to delete account' });
    }
});

module.exports = router;
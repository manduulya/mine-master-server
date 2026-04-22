// routes/worldMapRoutes.js
const express = require('express');
const { knex: db } = require('../db');
const { authenticateToken } = require('../middleware/auth');

const router = express.Router();

router.post('/world-map/progress', authenticateToken, async (req, res) => {
    const { revealed_countries } = req.body;

    if (!Array.isArray(revealed_countries)) {
        return res.status(400).json({ error: 'revealed_countries must be an array' });
    }

    try {
        await db('world_map_progress')
            .insert({
                user_id: req.user.id,
                revealed: JSON.stringify(revealed_countries),
                updated_at: db.fn.now(),
            })
            .onConflict('user_id')
            .merge(['revealed', 'updated_at']);

        res.json({ message: 'World map progress saved' });
    } catch (err) {
        console.error('Error saving world map progress:', err);
        res.status(500).json({ error: 'Failed to save world map progress' });
    }
});

router.get('/world-map/progress', authenticateToken, async (req, res) => {
    try {
        const row = await db('world_map_progress')
            .where({ user_id: req.user.id })
            .select('revealed')
            .first();

        const revealed_countries = row ? JSON.parse(row.revealed) : [];
        res.json({ revealed_countries });
    } catch (err) {
        console.error('Error fetching world map progress:', err);
        res.status(500).json({ error: 'Failed to fetch world map progress' });
    }
});

router.get('/world-map/leaderboard', async (req, res) => {
    const limit = parseInt(req.query.limit || '50');

    try {
        const rows = await db('world_map_progress as wmp')
            .join('users as u', 'wmp.user_id', 'u.id')
            .select('u.username', 'u.country_flag', 'wmp.revealed');

        const leaderboard = rows
            .map(row => {
                const countries = JSON.parse(row.revealed || '[]');
                return {
                    username: row.username,
                    country_flag: row.country_flag || 'international',
                    countries_revealed: countries.length,
                };
            })
            .filter(row => row.countries_revealed > 0)
            .sort((a, b) => b.countries_revealed - a.countries_revealed)
            .slice(0, limit);

        res.json(leaderboard);
    } catch (err) {
        console.error('World map leaderboard error:', err);
        res.status(500).json({ error: 'Failed to load world map leaderboard' });
    }
});

module.exports = router;

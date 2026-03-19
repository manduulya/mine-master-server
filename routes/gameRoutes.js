// routes/gameRoutes.js
const express = require('express');
const { knex: db } = require('../db');
const { authenticateToken } = require('../middleware/auth');



const router = express.Router();

router.post('/game/start', authenticateToken, (req, res) => {

    const { mine_count, mine_positions, level_id, hints, streak } = req.body;

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
                    hints: hints || 0,
                    streak: streak || 0,
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

router.get('/game/active', authenticateToken, (req, res) => {
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

router.get('/game/current', authenticateToken, async (req, res) => {

    try {
        const game = await db('game_states')
            .where({ user_id: req.user.id })
            .orderBy('updated_at', 'desc')
            .first();

        if (!game) {
            return res.status(404).json({ error: 'No active game found' });
        }

        res.json({
            game_id: game.id,
            level: game.level_id,
            mine_count: game.mine_count,
            mine_positions: JSON.parse(game.mine_positions),
            revealed_cells: JSON.parse(game.revealed_cells),
            flagged_cells: JSON.parse(game.flagged_cells),
            hints: game.hints,
            streak: game.streak,
            game_status: game.game_status,
        });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: 'Failed to load game state' });
    }
});

router.put('/game/update', authenticateToken, (req, res) => {

    const { game_id, revealed_cells, flagged_cells, hints } = req.body;

    if (!game_id || !Array.isArray(revealed_cells) || !Array.isArray(flagged_cells)) {
        return res.status(400).json({ error: 'Game ID, revealed cells, and flagged cells are required' });
    }

    const updateData = {
        revealed_cells: JSON.stringify(revealed_cells),
        flagged_cells: JSON.stringify(flagged_cells),
        updated_at: db.fn.now(),
    };

    if (typeof hints === 'number') {
        updateData.hints = hints;
    }

    db('game_states')
        .where({ id: game_id, user_id: req.user.id })
        .update(updateData)
        .then(changes => {
            if (!changes || changes === 0) return res.status(404).json({ error: 'No active game found' });
            res.json({ message: 'Game state updated successfully' });
        })
        .catch(err => {
            console.error(err);
            res.status(500).json({ error: 'Failed to update game state' });
        });
});

router.get('/game/:gameId/revealed', authenticateToken, async (req, res) => {
    const { gameId } = req.params;
    const game = await db('game_states').where({ id: gameId, user_id: req.user.id }).first();
    if (!game) return res.status(404).json({ error: 'Game not found' });
    res.json({ revealed_cells: JSON.parse(game.revealed_cells) });
});

router.get('/game/:gameId/flagged', authenticateToken, async (req, res) => {

    const { gameId } = req.params;
    const game = await db('game_states').where({ id: gameId, user_id: req.user.id }).first();
    if (!game) return res.status(404).json({ error: 'Game not found' });
    res.json({ flagged_cells: JSON.parse(game.flagged_cells) });
});

router.post('/game/finish', authenticateToken, (req, res) => {

    const { won, level, score, hints, streak } = req.body;
    console.log("Finishing game with data:", req.body);

    if (won === undefined || level === undefined || score === undefined) {
        return res.status(400).json({ error: 'Won status, level, and score are required' });
    }

    db.transaction(trx => {
        return trx('game_states')
            .where({ user_id: req.user.id, game_status: 'playing' })
            .first()
            .then(game => {
                if (!game) throw new Error('NO_ACTIVE_GAME');

                // Update game_states
                return trx('game_states')
                    .where({ id: game.id })
                    .update({
                        game_status: won ? 'won' : 'lost',
                        hints: hints || 0,
                        streak: streak || 0,
                        updated_at: db.fn.now()
                    })
                    .then(() => {
                        if (!won) return { score_id: null, is_new_record: false };

                        // Check if user has existing score
                        return trx('scores')
                            .where({ user_id: req.user.id })
                            .first()
                            .then(existingScore => {
                                if (!existingScore) {
                                    // No existing score, insert new
                                    return trx('scores')
                                        .insert({
                                            user_id: req.user.id,
                                            score,
                                            level,
                                            created_at: db.fn.now(),
                                            updated_at: db.fn.now()
                                        })
                                        .returning('id')
                                        .then(rows => ({
                                            score_id: rows[0]?.id || rows[0], // Handle different return formats
                                            is_new_record: true
                                        }));
                                }

                                // Always update with the new cumulative score and level
                                return trx('scores')
                                    .where({ user_id: req.user.id })
                                    .update({
                                        score,
                                        level,
                                        updated_at: db.fn.now()
                                    })
                                    .then(() => ({
                                        score_id: existingScore.id,
                                        is_new_record: score > existingScore.score
                                    }));
                            });
                    });
            });
    })
        .then(result => {
            console.log('✅ Game finished successfully:', result);
            res.json({
                message: 'Game finished successfully',
                won,
                score_id: result.score_id,
                score,
                level,
                is_new_record: result.is_new_record
            });
        })
        .catch(err => {
            console.error('❌ Error finishing game:', err);
            if (err.message === 'NO_ACTIVE_GAME') {
                return res.status(404).json({ error: 'No active game found' });
            }
            res.status(500).json({ error: 'Server error', details: err.message });
        });
});

module.exports = router;
// routes/flagsRoutes.js
const express = require('express');
const router = express.Router();

const { AVAILABLE_FLAGS } = require('../config/constants');

/**
 * GET /api/flags
 * Returns available country flags
 */
router.get('/flags', (req, res) => {
    res.json({ flags: AVAILABLE_FLAGS });
});

module.exports = router;
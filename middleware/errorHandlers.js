// middleware/errorHandlers.js

// 404 handler (must be AFTER your routes)
function notFoundHandler(req, res, next) {
    res.status(404).json({ error: 'Route not found' });
}

// Global error handler (must have 4 args)
function errorHandler(err, req, res, next) {
    console.error('Unhandled error:', err?.stack || err);
    res.status(500).json({ error: 'Internal Server Error' });
}

module.exports = { notFoundHandler, errorHandler };
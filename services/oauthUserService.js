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
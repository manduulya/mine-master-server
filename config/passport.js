const passport = require('passport');
const { knex: db } = require('../db');

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser((id, done) => {
    db('users').where({ id }).first()
        .then(user => done(null, user))
        .catch(err => done(err));
});

module.exports = passport;
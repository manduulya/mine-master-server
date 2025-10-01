// migrations/TIMESTAMP_create_users_table.js

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function (knex) {
    return knex.schema.createTable('users', function (table) {
        table.increments('id').primary();
        table.string('username', 50).notNullable().unique();
        table.string('email', 100).notNullable().unique();
        table.string('password_hash', 255);
        table.string('oauth_provider', 20);
        table.string('oauth_id', 100);
        table.string('country_flag', 50).defaultTo('international');
        table.timestamps(true, true); // created_at, updated_at

        // Indexes
        table.index('username');
        table.index('email');
        table.index(['oauth_provider', 'oauth_id']);
    });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function (knex) {
    return knex.schema.dropTable('users');
};
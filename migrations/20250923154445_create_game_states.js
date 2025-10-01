// migrations/TIMESTAMP_create_game_states_table.js

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function (knex) {
    return knex.schema.createTable('game_states', function (table) {
        table.increments('id').primary();
        table.integer('user_id').unsigned().notNullable()
            .references('id').inTable('users').onDelete('CASCADE');

        table.integer('level_id').notNullable();
        table.integer('mine_count').notNullable();

        table.text('mine_positions').notNullable();
        table.text('revealed_cells').notNullable();
        table.text('flagged_cells').notNullable();

        table.string('game_status', 20).notNullable().defaultTo('playing');
        table.timestamps(true, true);

        // Indexes
        table.index(['user_id']);                    // fast lookups per user
        table.index(['user_id', 'game_status']);     // fast "active game" lookup
        table.index(['level_id']);                   // optional, for level stats
    });
};


/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function (knex) {
    return knex.schema.dropTable('game_states');
};
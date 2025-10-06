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

        // Add hints and streak tracking
        table.integer('hints').defaultTo(0);
        table.integer('streak').defaultTo(0);

        table.string('game_status', 20).notNullable().defaultTo('playing');
        table.timestamps(true, true);

        // Indexes
        table.index(['user_id']);
        table.index(['user_id', 'game_status']);
        table.index(['level_id']);
    });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function (knex) {
    return knex.schema.dropTable('game_states');
};
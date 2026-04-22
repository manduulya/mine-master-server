/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.up = function (knex) {
    return knex.schema.createTable('world_map_progress', function (table) {
        table.integer('user_id').primary().references('id').inTable('users');
        table.text('revealed').notNullable().defaultTo('[]');
        table.timestamp('updated_at').defaultTo(knex.fn.now());
    });
};

/**
 * @param { import("knex").Knex } knex
 * @returns { Promise<void> }
 */
exports.down = function (knex) {
    return knex.schema.dropTable('world_map_progress');
};

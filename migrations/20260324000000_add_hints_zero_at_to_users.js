exports.up = function (knex) {
    return knex.schema.table('users', function (table) {
        table.timestamp('hints_zero_at').nullable().defaultTo(null);
    });
};

exports.down = function (knex) {
    return knex.schema.table('users', function (table) {
        table.dropColumn('hints_zero_at');
    });
};

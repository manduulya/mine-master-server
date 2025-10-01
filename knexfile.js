// module.exports = {
//     development: {
//         client: 'pg',
//         connection: process.env.DATABASE_URL,
//         migrations: {
//             directory: './migrations'
//         },
//         pool: { min: 2, max: 10 }
//     }
// };
module.exports = {
    development: {
        client: 'pg',
        connection: {
            host: 'localhost', // or 'localhost' if running Postgres on host
            port: 5432,
            user: 'postgres',
            password: 'password',
            database: 'minemaster'
        },
        migrations: {
            directory: './migrations'
        },
        pool: { min: 2, max: 10 }
    }
};
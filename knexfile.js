module.exports = {
    development: {
        client: 'pg',
        connection: {
            host: 'localhost',
            port: 5432,
            user: 'postgres',
            password: 'password',
            database: 'minemaster'
        },
        migrations: {
            directory: './migrations'
        },
        pool: { min: 2, max: 10 }
    },
    production: {
        client: 'pg',
        connection: {
            host: process.env.DB_HOST,
            port: process.env.DB_PORT,
            user: process.env.DB_USER,
            password: process.env.DB_PASSWORD,
            database: process.env.DB_NAME,
        },
        migrations: {
            directory: './migrations'
        },
        pool: { min: 2, max: 10 }
    }
};
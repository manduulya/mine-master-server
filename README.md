# Mine Master Server

Mine Master Server is a RESTful API backend for the Mine Master Minesweeper game. It is built with Node.js, Express, and SQLite, and supports user authentication (including OAuth), score tracking, leaderboards, and user statistics.

## Features

- User registration and login (JWT-based authentication)
- OAuth login with Google and Facebook
- Secure password hashing with bcrypt
- SQLite database (file-based, no setup required)
- Score submission and leaderboard endpoints
- User statistics and profile endpoints
- CORS support for frontend integration
- Graceful shutdown and error handling

## Requirements

- Node.js v14 or higher
- npm (Node package manager)

## Getting Started

1. **Clone the repository:**
   ```sh
   git clone https://github.com/yourusername/mine-master-server.git
   cd mine-master-server
   ```

2. **Install dependencies:**
   ```sh
   npm install
   ```

3. **Configure environment variables (optional):**
   - Create a `.env` file to override defaults for:
     - `PORT`
     - `JWT_SECRET`
     - `FACEBOOK_APP_ID`, `FACEBOOK_APP_SECRET`
     - `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
     - `BASE_URL`

4. **Start the server:**
   ```sh
   npm start
   ```
   Or for development with auto-reload:
   ```sh
   npm run dev
   ```

5. **The API will be available at:**  
   `http://localhost:3000/`

## API Endpoints

### Authentication

- `POST /api/auth/register` — Register a new user
- `POST /api/auth/login` — Login with username and password
- `GET /api/auth/google` — Google OAuth login
- `GET /api/auth/facebook` — Facebook OAuth login

### User

- `GET /api/user/profile` — Get user profile (JWT required)
- `GET /api/flags` — List available country flags

### Scores

- `POST /api/scores` — Submit a new score (JWT required)
- `GET /api/scores/user` — Get user's scores (JWT required)
- `GET /api/scores/user/best` — Get user's best scores (JWT required)
- `GET /api/leaderboard` — Get global leaderboard

### Statistics

- `GET /api/stats/user` — Get user statistics (JWT required)

### Health Check

- `GET /health` — Check server status

## Database

- Uses SQLite (`minemaster.db` file in project root)
- Tables: `users`, `scores`, `game_states`

## Development

- All code is in `server.js`
- Uses `nodemon` for development auto-reload (`npm run dev`)
- Add new routes or features as needed

## License

MIT

---

**Mine Master Server**  
Created by Ebo

# Member Portal Backend

## Deploy to Render
1. Upload these files to the root of a GitHub repository.
2. Create a PostgreSQL database in Render.
3. Create a Web Service from this repository.
4. Build command: `npm install`
5. Start command: `npm start`
6. Set these environment variables in Render:
   - `DATABASE_URL`: Render PostgreSQL Internal Database URL
   - `DATABASE_SSL`: `false` when using the internal URL and TLS is not required
   - `NODE_ENV`: `production`
   - `JWT_SECRET`: random secret at least 32 characters long
   - `FRONTEND_ORIGIN`: deployed frontend URL
7. Test `https://YOUR-BACKEND.onrender.com/api/health`.

The server creates the `members` table automatically. Passwords are stored as bcrypt hashes. The requested password-only login is ambiguous if multiple members share a password; for a multi-member site, use phone number plus password. Add proper sessions/JWT before exposing protected endpoints.

Never commit `.env` or put database credentials in frontend code.

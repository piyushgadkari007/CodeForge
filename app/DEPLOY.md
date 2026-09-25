# PhantomGuard Live Deployment

This project is a Flask app and is best deployed on Render, not Vercel.

## Recommended host

Use Render:
- https://dashboard.render.com

## Steps

1. Push this project to GitHub.
2. Log in to Render.
3. Click "New" -> "Web Service".
4. Connect your GitHub repository.
5. Use these settings:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `gunicorn wsgi:app --bind 0.0.0.0:$PORT`
6. Add environment variables:
   - `PHANTOMGUARD_SECRET` = a long random string
   - `GOOGLE_MAPS_API_KEY` = optional
   - `DATABASE_URL` = optional if using Postgres
7. Deploy.

## Important note about SQLite

This app supports SQLite by default for local development, but SQLite is not ideal for a production 24/7 server because the filesystem can reset.

For a production-grade setup, use a Postgres database and set `DATABASE_URL` in Render.

## Access

Once deployed, Render gives you a public URL like:

`https://your-app-name.onrender.com`

You can open that link anytime without running VS Code.

## Local run

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python -m flask --app PhantomGuard.app run
```

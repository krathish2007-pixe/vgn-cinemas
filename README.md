# VGN Cinemas — full-stack app

Node 22 server (no npm dependencies) + SQLite database + your original UI (public/index.html).

## Run locally
    node server.mjs        # http://localhost:3000
Env vars: PORT, DB_PATH (default ./data/vgn.db), SECRET (token signing key; auto-generated if unset).

## Deploy on Render
1. Push this folder to a GitHub repo.
2. render.com -> New -> Web Service -> pick the repo. Runtime: Docker (uses the Dockerfile).
3. Use a paid instance type and add a Disk: mount path /data, 1 GB.
4. Environment: DB_PATH=/data/vgn.db and SECRET=<long random string>.
5. Deploy. Your site goes live at https://<name>.onrender.com

Without a persistent disk the SQLite file is wiped on every deploy/restart.
Alternatives with volumes: Railway (Volume at /data), Fly.io (fly volumes).

## API
POST /api/signup, /api/login | GET /api/me | GET/POST /api/shows | DELETE /api/shows/:id
GET /api/shows/:id/taken?date=&time= | GET/POST /api/bookings

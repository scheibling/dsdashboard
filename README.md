# DSDashboard


![Dashboard](https://github.com/user-attachments/assets/7b63904a-fbf1-4300-b307-af7b90ac7908)

![Settings](https://github.com/user-attachments/assets/8de41972-cc29-407c-96d2-33cb8476b88e)









This is the complete production version with a clean normal dashboard mode and a password-protected edit mode.

## What is included

Normal mode shows only the dashboard, search, stats, service sections and cards.

Edit mode unlocks:

- Password-protected edit mode
- Add, edit and delete hosts
- Add, edit and delete sections / blocks
- Drag and drop sorting for sections and hosts
- Import configuration from config.json
- Export configuration to config.json
- Automatic backup before every save
- Manual backup creation
- Backup list with download, restore and delete
- Restore from local config file
- Icon picker
- Section color picker
- Live host preview while editing
- Mobile preview
- Toast notifications
- Dark / light theme switch
- Server-side config saving to /site/config.json
- Health/status integration through check-services.sh
- Production security headers
- Server-side session cookie with CSRF protection
- Login rate limiting
- Password hashing with scrypt

## Folder layout

After extracting, keep the structure like this:

```text
dashboard-production-final/
├── compose.yaml
├── Dockerfile
├── server.js
├── start.sh
├── check-services.sh
├── package.json
├── .env.example
├── site/
│   ├── index.html
│   ├── app.js
│   ├── style.css
│   ├── config.json
│   └── status.json
└── data/
    └── backups/
```

## First start

1. Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

2. Edit `.env` and change the password:

```bash
nano .env
```

Set a real password:

```text
DASHBOARD_ADMIN_PASSWORD=your-long-secure-password
```

3. Start the dashboard:

```bash
docker compose up -d --build
```

4. Open:

```text
http://SERVER-IP:8080
```

## Important password note

The password is written as a secure hash to `data/security.json` on first start.

If you start once with the default password and later change `.env`, the old hash in `data/security.json` remains active. Change the password inside the Security panel, or stop the container and remove `data/security.json` before starting again.

Default fallback password, only if you do not set `.env`:

```text
change-me-now
```

Change it immediately.

## Existing installation using /opt/dashboard/site

If your current files live in `/opt/dashboard/site`, you can either copy this full folder there or adjust the volume in `compose.yaml`:

```yaml
volumes:
  - /opt/dashboard/site:/site
  - /opt/dashboard/data:/data
```

Then put these frontend files in `/opt/dashboard/site`:

```text
index.html
app.js
style.css
config.json
status.json
```

The root files `server.js`, `Dockerfile`, `compose.yaml`, `start.sh`, `check-services.sh` should stay together in the project root.

## Status checks

`start.sh` runs `check-services.sh` every 60 seconds by default.

The checker reads:

```text
/site/config.json
```

and writes:

```text
/site/status.json
```

You can change the interval in `.env`:

```text
STATUS_INTERVAL=60
```

## HTTPS / reverse proxy

For internet-facing use, put the dashboard behind HTTPS and set:

```text
COOKIE_SECURE=true
```

Only do that when the browser reaches the dashboard through HTTPS.



## 🖼️ Adding new icons

New icons can be added directly in: /site/app.js

Inside the icon picker array, simply append new entries. Emoji and text icons are supported.

They will appear instantly in the UI — no rebuild needed.



## Useful commands

Rebuild and start:

```bash
docker compose up -d --build
```

View logs:

```bash
docker compose logs -f
```

Stop:

```bash
docker compose down
```

Run a manual status check inside the container:

```bash
docker exec dashboard /bin/bash /app/check-services.sh
```

## Docker Run & Docker Compose

📁 Required persistent folders - Start with creating these folders on the host:
```text
/your-path/site
/your-path/data
```

When not building from source you need to copy the content from the repositorys site/ and data/ folders to yours.
This will provide you with a basic default setup that you can modify to your own liking.

By doing this before you start the container all your settings, password, backups and modifications to icons etc will be persistent when updating to a new image.



## First start

1. Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

2. Edit `.env` and change the password:

```bash
nano .env
```

Set a real password:

```text
DASHBOARD_ADMIN_PASSWORD=your-long-secure-password
```

## Docker Run

```bash
docker run -d \
  --name dsdashboard \
  --env-file .env \
  -p 8080:3000 \
  -v /your-path/site:/site \
  -v /your-path/data:/data \
  d0sn/dsdashboard:latest
```

## Docker Compose (recommended)

```yaml
services:
  dsdashboard:
    image: d0sn/dsdashboard:latest
    container_name: dsdashboard
    env_file: .env
    ports:
      - "8080:3000"
    volumes:
      - /your-path/site:/site
      - /your-path/data:/data
    restart: unless-stopped

volumes:
  dsdashboard-site:
  dsdashboard-data:
```

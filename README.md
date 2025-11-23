# TWdrops

> Twitch drops farmer with an embedded Playwright browser, profile isolation, and a slick control panel.

![Dashboard screenshot](path/to/dashboard.png)

![Profile switcher](path/to/profile-switcher.png)

## Features
- Embedded, headless Playwright browser you can drive from the UI (click, type, scroll, zoom).
- Cookie capture and Twitch account stats viewer (display name, partner/affiliate, created at, bio, avatar).
- Active drops list with reward progress bars; auto-fetch live channels for a selected drop.
- Background farming: auto-play/mute stream, queue next channels, and keep running even if you switch profiles.
- Multi-profile support: each profile has its own Chrome data dir and cookie cache; create/delete/switch from the header.
- Auto-channel helper to pick a live stream for the selected game/drop.

## Requirements
- Node.js 18+ (or 20+ recommended).
- Playwright is already in `package-lock`. System packages for Chromium must be available if you containerize (see note below).

## Quick start
```bash
npm install
npm start
# server runs on http://localhost:3000
```

Then open the UI in your browser. From there:
1) Create/select a profile (top-right).  
2) Open the embedded browser, log into Twitch.  
3) Capture cookies.  
4) Refresh drops, pick a drop/channel, and start farming.  
5) Use Stop farming when you want to halt that profile’s session.

## Profile data & persistence
- Profile data and cookies live in `.twdrops-profile/` (default) and subfolders for each profile.
- Keep this folder if you want to persist sessions across restarts. Mount it as a volume in Docker.
- Each profile runs its own background farming context; switching profiles does not stop others.

## Environment variables (optional)
- `TW_CLIENT_INTEGRITY` – client integrity token (if you prefer to inject yours).
- `TW_DEVICE_ID` – device id override.
- `TW_CLIENT_ID` – Twitch client id (defaults to `kimne78kx3ncx6brgo4mv6wki5h1ko`).

## Docker (in `docker/`)
Uses the Playwright base image so Chromium dependencies are already present.
- Build: `docker build -t twdrops -f docker/Dockerfile .`
- Run: `docker run -p 3000:3000 -v twdrops_profile:/app/.twdrops-profile twdrops`
- Browse: `http://localhost:3000` (profile data persists in the `twdrops_profile` volume)

## Useful scripts
- `npm start` – run server (Express + Playwright + static frontend).

## Notes & tips
- The embedded browser uses a spoofed desktop UA, locale `es-ES`, timezone `Europe/Madrid`, headless.
- If drops fail to load, re-capture cookies for the active profile.
- The queue is per-profile; adding channels while farming appends to that profile’s queue.

## Contributing
PRs welcome. Keep changes ASCII, avoid auto-formatting large files, and mind the multi-profile logic.

## License
MIT (see LICENSE if present). Feel free to adapt for personal use.

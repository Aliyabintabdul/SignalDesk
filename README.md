# SignalDesk

Manual security incident tracker — a dark investigation console for recording and resolving incidents.

A personal full-stack portfolio MVP: plain HTML/CSS/JavaScript frontend, Python standard-library backend and SQLite. It runs independently with its own database. All sample data is fictional; there are no real users, clients or production deployments.

## Run it
Requires Python 3.10+ only — no pip packages, no npm, no CDN. From this folder:

```
py server.py --port 8005               # Windows
python3 server.py --port 8005          # macOS / Linux
py server.py --port 8005 --seed-demo   # optional: add the fictional demo account
```
Open http://localhost:8005 and stop with Ctrl+C. The database `data.sqlite3` is created on first launch (override with `DB_PATH`). To run all five projects at once use `start-all.bat` / `stop-all.bat` in the parent folder.

**Demo access (optional, local only):** `--seed-demo` creates `demo@example.com` / `DemoPass123!` (override with `DEMO_PASSWORD`) filled with clearly fictional sample data, marked in the UI with a "Demo workspace" banner. Seeding is refused when `APP_ENV=production`, and never overwrites an existing demo account. Any visitor can also register a fresh, empty, private account.

## Tests
```
py -m unittest discover -s tests
```
Integration tests start the real server on a free port with a throwaway database and exercise it over HTTP: registration/login/logout, session invalidation after logout, CSRF and origin rejection, login rate limiting, account isolation, the domain rules below, CSV formula neutralisation and persistence across a restart.

## Features
- **Incidents**: auto-numbered reference (INC-0001 per account), title, description, category, severity (Low/Medium/High/Critical), status (Open → Investigating → Contained → Resolved), review date, detected-at time, created/updated/resolved timestamps and resolution notes.
- **Incident queue + investigation pane** (master–detail): search (title, reference, asset, category), status/severity/category filters, overdue toggle, sorting and CSV export of the filtered queue.
- **Triage panel** for quick status/severity changes; **comments** with author and timestamp; an **investigation timeline** combining comments with the activity history of status, severity, asset and detail changes.
- **Assets**: name, type, environment, criticality, owner, identifier, notes; link any number of assets to an incident; asset detail shows linked incidents. Deleting an asset unlinks it and records that in each incident's history.
- **Overview**: open incidents by severity, status counts, overdue reviews, resolved in the last 30 days, mean time to resolve, most-affected assets and recent activity — all from stored records.

## Domain rules (enforced on the server)
- **Resolution notes are required** (≥ 10 characters) before an incident can be Resolved — enforced on create, edit and triage, and by a database CHECK constraint. Reopening clears the resolved timestamp.
- Every status and severity change is written to the activity history with old → new values. Comments are append-only.
- Assets can only be linked within your own account; incident numbers are per account.

## Data model
```
users ─┬─< assets ─┐
       └─< incidents ─┬─< incident_assets >─┘
                      ├─< comments
                      └─< activity (kind, from_value, to_value)
```
`incidents(number, title, description, category, severity, status, review_date, detected_at, resolution_notes, resolved_at)` · `assets(name, type, environment, criticality, owner, identifier, notes)`

## API
JSON over HTTP; authenticated with the session cookie plus `X-CSRF-Token` on mutations. Auth: `POST /api/register|login|logout`, `GET /api/session`, `GET /api/health`, `GET /api/meta`.
`GET /api/dashboard` · `GET|POST /api/incidents` (`q, status, severity, category, asset_id, overdue, sort`) · `GET|PUT|DELETE /api/incidents/:id` · `POST /api/incidents/:id/triage` · `POST /api/incidents/:id/comments` · `GET|POST /api/assets` · `GET|PUT|DELETE /api/assets/:id` · `GET /api/export/incidents`

## Project structure
`server.py` domain schema, migrations, validation and routes · `core.py` shared foundation (identical in all five projects) · `frontend/` `index.html`, `style.css`, `app.js` (this product's UI) and `lib.js` (shared helpers) · `tests/` integration tests.

## Security & reliability (shared foundation in `core.py`)
- Passwords hashed with PBKDF2-HMAC-SHA256 (200,000 iterations, per-user salt); constant-time comparison.
- Sessions: random 256-bit token in an `HttpOnly`, `SameSite=Lax` cookie (`Secure` in production); only a SHA-256 hash is stored. Sessions expire after 8 hours (`SESSION_TTL_SECONDS`) and are deleted on logout, so a copied cookie stops working.
- CSRF: every POST/PUT/DELETE needs the per-session `X-CSRF-Token` header and a same-origin `Origin`; JSON-only request bodies.
- Login rate limiting: 5 failed attempts per email+IP and 30 per IP per 15 minutes (HTTP 429). Registration: 10 accounts per IP per hour.
- Account isolation: every query is scoped to the signed-in user's id; other users' IDs return 404.
- Server-side validation with field-level messages; parameterised SQL everywhere; each mutating request runs in one `BEGIN IMMEDIATE` transaction (all related writes succeed or none do).
- Consistent errors: `{"error": "...", "code": "...", "fields": {...}}` with appropriate HTTP status codes.
- CSV exports neutralise spreadsheet formulas (cells starting with `= + - @ |`, tab or CR are prefixed with `'`).
- Static files are served with a strict Content-Security-Policy (no inline scripts), `nosniff`, `DENY` framing and path-traversal protection.
- Schema migrations are versioned (`PRAGMA user_version`); an existing database is copied to `data.backup-v<N>-<timestamp>.sqlite3` before migrating. Data from the original single-table version (`records`) is migrated into the new tables and the old table is kept as `legacy_records`.

## Limitations
**SignalDesk is a manual tracker.** It does not detect attacks, monitor systems, ingest logs, run automated or AI analysis, or integrate with a SIEM, ticketing or paging system — every incident is entered by a person. No evidence file uploads, team assignment or notifications. Not a substitute for an organisation's incident-response tooling or obligations.

The files `server.legacy.py`, `migrations/001_saas.sql` and `data.pre-saas.sqlite3` are leftovers from an earlier, unfinished multi-tenant attempt; they are not used by this version and are excluded from the source ZIP.
Other: single-user accounts, no password reset, no pagination beyond sensible limits, English UI only, dates displayed in the browser's locale. Visual design was checked in a desktop browser and at mobile width, but not across every browser.

## Production deployment requirements
This is a local portfolio MVP. Before exposing it publicly you would need at least:
- HTTPS termination (reverse proxy such as Caddy/Nginx) and `APP_ENV=production` (enables `Secure` cookies and disables demo seeding).
- A production WSGI/ASGI-grade server or a hardened proxy in front of `ThreadingHTTPServer`, request timeouts and process supervision (systemd, a container restart policy, etc.).
- Persistent storage with scheduled backups for the SQLite file (or migration to PostgreSQL for concurrent multi-instance use).
- Account recovery (password reset by email), email verification and optionally MFA — none are implemented.
- Centralised logging/monitoring, and a shared rate-limit store if running more than one instance.
- Review of privacy/data-retention obligations for the data you store.

# KIU Ghost Worker Detection Demo

This is a refined second version of a group project, building on the original concept with a more complete role-aware workflow and employee review experience.

A responsive, local-first HR dashboard prototype. The Ghost Worker workspace is backed by SQLite sample records and a Python standard-library API. Authentication, session validation, and role checks run on the server; passwords are stored as PBKDF2 hashes rather than in browser code.

## Run locally

Python 3.10 or later is required. No third-party packages are needed.

```powershell
py server.py
```

If `py` is not available, run `python server.py`. Open <http://127.0.0.1:8080>. The VS Code launch configuration uses this URL; start the server before launching Chrome.

The SQLite database is created as `.ghost-worker.sqlite3` on first run. To restore the original sample users, employee records, alerts, and scan history, stop the server and delete that file. Set `GHOST_WORKER_DB` to use a different database path. The default listener is `127.0.0.1`; `GHOST_WORKER_HOST` and `GHOST_WORKER_PORT` can override it for development.

## Local demo accounts

These seeded credentials are intentionally simple and public for local evaluation. They are not appropriate for deployment or real employee data. Change or remove the seed accounts before sharing or exposing the app.

| Email | Password | Role |
| --- | --- | --- |
| `admin@kiu` | `hr` | Administrator |
| `payroll@kiu` | `payroll123` | Payroll Administrator |
| `finance@kiu` | `finance123` | Finance Controller |
| `hr@kiu` | `hr123` | HR Officer |
| `investigator@kiu` | `investigate` | Investigation Officer |
| `auditor@kiu` | `audit123` | Internal Auditor |

## Access control

The server issues a random session token in an `HttpOnly`, `SameSite=Strict` cookie (eight hours by default, or 30 days when “Stay signed in” is selected). Only a hash of the token is stored in SQLite. State-changing requests require the session CSRF token. Every Ghost Worker data request checks the authenticated account's role on the server; only Administrator and Investigation Officer can run scans. The navigation visibility in the browser is for usability and is not the security boundary. Dashboard shortcuts, action alerts, and notifications are filtered to the signed-in role; Finance and Audit users receive home cards for only their permitted workspaces.

The sample scan evaluates attendance recency, biometric verification, and payroll-active status for the seeded sample employees. Alerts and scan history are persisted to the local database. These are synthetic records and illustrative rules, not a validated fraud-detection model. Other dashboard sections remain front-end demo views; they are not yet backed by protected APIs and must not be used for operational employee or payroll data.

## Risk scoring & investigation workflow

Each flagged employee receives a **0–100 risk score**:

| Points | Signal |
| --- | --- |
| +40 | No attendance for ≥ 60 days |
| +25 | No attendance for 30–59 days |
| +30 | Biometric verification failed |
| +20 | Payroll still active while flagged |

Levels: **Low** (0–24), **Medium** (25–49), **High** (50–74), **Critical** (75–100).

Investigation Officers and Administrators can:

- Change investigation status: Open → Under Investigation → Confirmed Ghost / Cleared / False Positive
- Add timestamped notes on the employee profile
- Status is preserved across rescans

## Alert search, filters & export

On the Ghost Workers alerts table you can:

- Search by employee name or ID
- Filter by risk level, investigation status, and department
- Export the **currently filtered** list as CSV (`Export CSV` on the panel, or the top-bar Export button while on Ghost Workers)

## Employees, attendance & payroll APIs

These sections now load sample data from the local API instead of static front-end arrays:

| Endpoint | Privilege | Data |
| --- | --- | --- |
| `GET /api/employees` | employees | Directory + summary counts |
| `GET /api/attendance` | attendance / employees / ghost-workers | Per-employee attendance snapshot |
| `GET /api/payroll` | payroll-finance / export | Payroll runs by period |

Delete `.ghost-worker.sqlite3` and restart the server if you need to re-seed attendance and payroll sample rows.

## Verify

```powershell
py -m unittest -v
```

## Deployment warning

This is a development demo, not a production HR or payroll system. It binds to localhost by default and has no account administration, password reset, rate limiting, audit export, HTTPS termination, backups, or real identity/payroll integrations. Do not expose it to a network or enter real staff data without a security review and production-grade deployment controls.

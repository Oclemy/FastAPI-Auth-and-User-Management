# 🔐 FastAPI Auth & User Management

One-file FastAPI authentication system with JWT tokens, user management, admin panel, and built-in frontend.

## One Click Deploy

[![Deploy on Railway](https://railway.com/button.svg)](https://railway.com/deploy/1HiSNf?referralCode=-Xd4K_&utm_medium=integration&utm_source=template&utm_campaign=generic)

## Quick Start (Local)

```bash
pip install -r requirements.txt
python main.py
# Open http://localhost:8080
```


| Variable | Default | Description |
|---|---|---|
| `SECRET_KEY` | auto-generated | JWT signing key (set for persistence across redeploys) |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `30` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `APP_NAME` | `FastAPI Auth` | Shown in UI |

5. To create the **one-click deploy template**: Railway Dashboard → Project → Settings → Generate Template

## Features

- Register / Login (email or username) / Logout
- JWT access + refresh tokens with rotation
- Token revocation (logout invalidates tokens)
- Profile view & edit, password change, account deletion
- Admin panel: list users, toggle active/admin status
- Auto-creates tables on startup
- SQLite locally, PostgreSQL on Railway
- Built-in frontend + Swagger UI at `/docs`

## API Endpoints

```
POST   /api/auth/register          → Create account, get tokens
POST   /api/auth/login             → Login, get tokens
POST   /api/auth/refresh           → Rotate refresh token
POST   /api/auth/logout            → Revoke token
GET    /api/users/me               → Get profile
PATCH  /api/users/me               → Update profile
POST   /api/users/me/change-password
DELETE /api/users/me               → Delete account
GET    /api/admin/users            → List all users (admin)
PATCH  /api/admin/users/{id}/toggle-active
PATCH  /api/admin/users/{id}/toggle-admin
GET    /api/health
```

## Making First Admin

Register your first user via the UI, then connect to the Railway PostgreSQL and run:
```sql
UPDATE users SET is_admin = true WHERE id = 1;
```

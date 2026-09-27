# Kargah Anbar - Workshop Inventory Management System

A workshop inventory management app with cloud sync via Cloudflare Workers + D1 Database.

## Features
- Tool inventory management
- Sheet (wood/MDF) tracking
- Hardware (fasteners, hinges, rails) management
- Invoice/template system with auto-numbering
- Job tracking with tool checkout
- Dark/Light theme
- Export/Import backup
- **Cloud sync** with Cloudflare D1

## Architecture
- **Frontend**: Static HTML/CSS/JS on GitHub Pages
- **Backend**: Cloudflare Worker API
- **Database**: Cloudflare D1 (SQLite-compatible)

## Deployment Status
- ✅ Cloudflare Worker: https://kargah-anbar-api.itsfordecosahand.workers.dev
- ✅ GitHub Pages: Deploying...

## API Endpoints
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/tools | List all tools |
| POST | /api/tools | Create tool |
| PUT | /api/tools/:id | Update tool |
| DELETE | /api/tools/:id | Delete tool |
| GET | /api/sheets | List all sheets |
| POST | /api/sheets | Create sheet |
| PUT | /api/sheets/:id | Update sheet |
| DELETE | /api/sheets/:id | Delete sheet |
| GET | /api/hardware | List all hardware |
| POST | /api/hardware | Create hardware |
| PUT | /api/hardware/:id | Update hardware |
| DELETE | /api/hardware/:id | Delete hardware |
| GET | /api/templates | List all templates |
| POST | /api/templates | Create template |
| PUT | /api/templates/:id | Update template |
| DELETE | /api/templates/:id | Delete template |
| GET | /api/jobs | List all jobs |
| POST | /api/jobs | Create job |
| PUT | /api/jobs/:id | Update job |
| DELETE | /api/jobs/:id | Delete job |
| GET | /api/invoice-number | Get next invoice number |
| GET | /health | Health check |

## Setup Local Development
```bash
cd frontend
npx serve .
```

## Security Notes
- No sensitive credentials in frontend code
- API_BASE configured in index.html
- Worker secret keys stored in Cloudflare dashboard

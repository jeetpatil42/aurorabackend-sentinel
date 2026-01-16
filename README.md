# Aurora Sentinel Backend

Node.js + Express backend API with WebSocket support.

## Setup

1. Install dependencies:
```bash
npm install
```

2. Configure environment:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Set up database:
- Use Supabase or PostgreSQL
- Run the SQL schema from `src/db/schema.sql`

4. Run migrations:
```bash
npm run migrate
```

5. Start development server:
```bash
npm run dev
```

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/verify` - Verify OTP
- `POST /api/auth/login` - Login
- `GET /api/auth/me` - Get current user

### SOS
- `POST /api/sos` - Create SOS event
- `GET /api/sos` - Get SOS events
- `GET /api/sos/:id` - Get SOS event by ID
- `PATCH /api/sos/:id/status` - Update SOS status

### Presentation Mode
- `GET /api/presentation` - Get presentation mode status
- `POST /api/presentation/toggle` - Toggle presentation mode

## WebSocket Events

### Client → Server
- `join_sos` - Join SOS room
- `leave_sos` - Leave SOS room
- `live_feed` - Send live feed data

### Server → Client
- `new_sos_alert` - New SOS alert
- `sos_status_update` - SOS status update
- `live_feed` - Live feed data
"# aurorabackend-sentinel" 

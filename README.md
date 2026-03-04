# GBV Management Information System

A comprehensive case management system for Gender-Based Violence (GBV) cases for the Rwanda National Police.

## Features

- **Case Management**: Register, track, and manage GBV cases
- **User Management**: Role-based access control for officers, investigators, commanders, and admins
- **Dashboard Analytics**: Real-time statistics and case insights
- **Investigation Logs**: Track case progress and updates
- **Secure Authentication**: Login system with encrypted passwords
- **Database Integration**: SQLite database for persistent data storage

## Prerequisites

- Node.js (v14 or higher)
- npm (Node Package Manager)

## Installation

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Start the Server**
   ```bash
   npm start
   ```
   
   Or for development with auto-restart:
   ```bash
   npm run dev
   ```

3. **Access the Application**
   Open your web browser and navigate to:
   ```
   http://localhost:3000
   ```

## Default Login Credentials

- **Username**: `admin`
- **Password**: `admin123`
- **Service Number**: `RNP001`

**Important**: Change the default password after first login!

## Database

The system uses SQLite database (`GBV_MIS.db`) which will be automatically created on first run with the following tables:

- `users` - System users and authentication
- `cases` - GBV case records
- `case_updates` - Case activity log
- `evidence` - Evidence tracking
- `referrals` - External referrals

## API Endpoints

### Authentication
- `POST /api/login` - User login

### Cases
- `GET /api/cases` - List all cases (with filters)
- `GET /api/cases/:id` - Get single case
- `POST /api/cases` - Create new case
- `PUT /api/cases/:id` - Update case
- `GET /api/cases/:id/updates` - Get case updates
- `POST /api/cases/:id/updates` - Add case update

### Statistics
- `GET /api/stats` - Dashboard statistics
- `GET /api/stats/by-type` - Cases by type

### Users
- `GET /api/users` - List all users
- `POST /api/users` - Create new user

## User Roles

1. **Admin** - Full system access
2. **Commander** - Oversight and reporting
3. **Investigator** - Case investigation and updates
4. **Data Entry** - Case registration and basic operations

## Security Features

- Password hashing with bcrypt
- Role-based access control
- Session management
- Audit logging
- Data confidentiality protections

## Project Structure

```
GBV_PROJECT/
├── server.js           # Backend API server
├── GBV_MIS.html       # Frontend application
├── GBV_MIS.db         # SQLite database (auto-generated)
├── RNP.png            # Logo image
├── package.json       # Node.js dependencies
└── README.md          # This file
```

## Development

To make changes:

1. **Frontend**: Edit `GBV_MIS.html`
2. **Backend API**: Edit `server.js`
3. **Database Schema**: Modify the `initializeDatabase()` function in `server.js`

## Troubleshooting

### Port Already in Use
If port 3000 is already in use, you can change it in `server.js`:
```javascript
const PORT = 3001; // Change to any available port
```

### Database Issues
To reset the database, simply delete `GBV_MIS.db` and restart the server. A fresh database will be created.

### CORS Errors
If you encounter CORS errors, ensure the server is running and the `API_URL` in the HTML file matches your server address.

## Support

For issues or questions, contact the ICT Unit at RNP Headquarters.

## License

Confidential - Rwanda National Police Internal Use Only

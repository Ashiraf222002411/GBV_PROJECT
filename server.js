const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const cors = require('cors');
const bcrypt = require('bcryptjs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

// Database connection
const db = new sqlite3.Database('./GBV_MIS.db', (err) => {
  if (err) {
    console.error('Error connecting to database:', err);
    process.exit(1);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

// Handle database errors
db.on('error', (err) => {
  console.error('Database error:', err);
});

// Initialize database schema
function initializeDatabase() {
  db.serialize(() => {
    // Users table
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      service_number TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'investigator', 'commander', 'data_entry')),
      station TEXT,
      email TEXT,
      phone TEXT,
      is_active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login DATETIME
    )`);

    // Cases table
    db.run(`CREATE TABLE IF NOT EXISTS cases (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_number TEXT UNIQUE NOT NULL,
      victim_name TEXT NOT NULL,
      victim_age INTEGER,
      victim_gender TEXT,
      victim_phone TEXT,
      victim_address TEXT,
      incident_type TEXT NOT NULL,
      incident_date DATE NOT NULL,
      incident_time TIME,
      incident_location TEXT NOT NULL,
      incident_description TEXT,
      suspect_name TEXT,
      suspect_age INTEGER,
      suspect_gender TEXT,
      suspect_address TEXT,
      relationship_to_victim TEXT,
      status TEXT DEFAULT 'Open' CHECK(status IN ('Open', 'Under Investigation', 'Closed', 'Referred')),
      priority TEXT DEFAULT 'Normal' CHECK(priority IN ('Low', 'Normal', 'High', 'Urgent')),
      assigned_to INTEGER,
      reported_by INTEGER NOT NULL,
      station TEXT NOT NULL,
      province TEXT,
      district TEXT,
      sector TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (assigned_to) REFERENCES users(id),
      FOREIGN KEY (reported_by) REFERENCES users(id)
    )`);

    // Case updates/notes table
    db.run(`CREATE TABLE IF NOT EXISTS case_updates (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      update_type TEXT NOT NULL CHECK(update_type IN ('Note', 'Status Change', 'Evidence', 'Interview', 'Action Taken')),
      description TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (case_id) REFERENCES cases(id),
      FOREIGN KEY (user_id) REFERENCES users(id)
    )`);

    // Evidence table
    db.run(`CREATE TABLE IF NOT EXISTS evidence (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL,
      evidence_type TEXT NOT NULL,
      description TEXT NOT NULL,
      collected_by INTEGER NOT NULL,
      collected_date DATE NOT NULL,
      storage_location TEXT,
      file_path TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (case_id) REFERENCES cases(id),
      FOREIGN KEY (collected_by) REFERENCES users(id)
    )`);

    // Referrals table
    db.run(`CREATE TABLE IF NOT EXISTS referrals (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id INTEGER NOT NULL,
      referred_to TEXT NOT NULL,
      referred_by INTEGER NOT NULL,
      referral_date DATE NOT NULL,
      referral_reason TEXT,
      status TEXT DEFAULT 'Pending' CHECK(status IN ('Pending', 'Accepted', 'Completed')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (case_id) REFERENCES cases(id),
      FOREIGN KEY (referred_by) REFERENCES users(id)
    )`);

    // Create default admin user
    const defaultPassword = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (service_number, password_hash, full_name, role, station) 
            VALUES ('admin', ?, 'System Administrator', 'admin', 'HQ')`, [defaultPassword], (err) => {
      if (err) {
        console.error('Error creating default admin user:', err);
      } else {
        console.log('Default admin user ensured');
      }
    });

    console.log('Database initialized successfully');
  });
}

// ==================== ROUTES ====================

// Serve the main HTML file
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'GBV_MIS.html'));
});

// ==================== AUTHENTICATION ====================

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  db.get('SELECT * FROM users WHERE service_number = ? AND is_active = 1', 
    [username], 
    async (err, user) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const validPassword = await bcrypt.compare(password, user.password_hash);
      if (!validPassword) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      // Update last login
      db.run('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', [user.id]);

      res.json({
        success: true,
        user: {
          id: user.id,
          service_number: user.service_number,
          fullName: user.full_name,
          role: user.role,
          station: user.station
        }
      });
    });
});

// ==================== CASES ====================

// Get all cases with filters
app.get('/api/cases', (req, res) => {
  const { status, priority, station, search } = req.query;
  
  let query = `SELECT c.*, u1.full_name as assigned_to_name, u2.full_name as reported_by_name 
               FROM cases c 
               LEFT JOIN users u1 ON c.assigned_to = u1.id 
               LEFT JOIN users u2 ON c.reported_by = u2.id 
               WHERE 1=1`;
  const params = [];

  if (status) {
    query += ` AND c.status = ?`;
    params.push(status);
  }
  if (priority) {
    query += ` AND c.priority = ?`;
    params.push(priority);
  }
  if (station) {
    query += ` AND c.station = ?`;
    params.push(station);
  }
  if (search) {
    query += ` AND (c.case_number LIKE ? OR c.victim_name LIKE ? OR c.suspect_name LIKE ?)`;
    params.push(`%${search}%`, `%${search}%`, `%${search}%`);
  }

  query += ` ORDER BY c.created_at DESC`;

  db.all(query, params, (err, rows) => {
    if (err) {
      console.error('Error fetching cases:', err);
      return res.status(500).json({ error: 'Database error', details: err.message });
    }
    res.json(rows || []);
  });
});

// Get single case
app.get('/api/cases/:id', (req, res) => {
  db.get(`SELECT c.*, u1.full_name as assigned_to_name, u2.full_name as reported_by_name 
          FROM cases c 
          LEFT JOIN users u1 ON c.assigned_to = u1.id 
          LEFT JOIN users u2 ON c.reported_by = u2.id 
          WHERE c.id = ?`, 
    [req.params.id], 
    (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row) {
        return res.status(404).json({ error: 'Case not found' });
      }
      res.json(row);
    });
});

// Create new case
app.post('/api/cases', (req, res) => {
  const {
    victim_name, victim_age, victim_gender, victim_phone, victim_address,
    incident_type, incident_date, incident_time, incident_location, incident_description,
    suspect_name, suspect_age, suspect_gender, suspect_address, relationship_to_victim,
    priority, station, province, district, sector, reported_by
  } = req.body;

  console.log('Received case data:', req.body);

  // Validate required fields
  if (!victim_name || !incident_type || !incident_date || !incident_location || !station || !reported_by) {
    console.error('Missing required fields');
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Generate case number
  const year = new Date().getFullYear();
  const caseNumber = `GBV-${year}-${Date.now().toString().slice(-6)}`;

  const query = `INSERT INTO cases (
    case_number, victim_name, victim_age, victim_gender, victim_phone, victim_address,
    incident_type, incident_date, incident_time, incident_location, incident_description,
    suspect_name, suspect_age, suspect_gender, suspect_address, relationship_to_victim,
    priority, station, province, district, sector, reported_by
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;

  db.run(query, [
    caseNumber, victim_name, victim_age, victim_gender, victim_phone, victim_address,
    incident_type, incident_date, incident_time, incident_location, incident_description,
    suspect_name, suspect_age, suspect_gender, suspect_address, relationship_to_victim,
    priority, station, province, district, sector, reported_by
  ], function(err) {
    if (err) {
      console.error('Database error creating case:', err);
      return res.status(500).json({ error: 'Failed to create case: ' + err.message });
    }
    console.log('Case created successfully:', caseNumber);
    res.json({ success: true, caseId: this.lastID, caseNumber });
  });
});

// Update case
app.put('/api/cases/:id', (req, res) => {
  const { id } = req.params;
  const updates = req.body;
  
  const fields = Object.keys(updates).map(key => `${key} = ?`).join(', ');
  const values = [...Object.values(updates), id];

  db.run(`UPDATE cases SET ${fields}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`, 
    values, 
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to update case' });
      }
      res.json({ success: true });
    });
});

// ==================== CASE UPDATES ====================

// Get case updates
app.get('/api/cases/:id/updates', (req, res) => {
  db.all(`SELECT cu.*, u.full_name as updated_by_name 
          FROM case_updates cu 
          LEFT JOIN users u ON cu.user_id = u.id 
          WHERE cu.case_id = ? 
          ORDER BY cu.created_at DESC`, 
    [req.params.id],
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
    });
});

// Add case update
app.post('/api/cases/:id/updates', (req, res) => {
  const { update_type, description, user_id } = req.body;
  
  db.run(`INSERT INTO case_updates (case_id, user_id, update_type, description) 
          VALUES (?, ?, ?, ?)`,
    [req.params.id, user_id, update_type, description],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Failed to add update' });
      }
      res.json({ success: true, updateId: this.lastID });
    });
});

// ==================== STATISTICS ====================

// Dashboard statistics
app.get('/api/stats', (req, res) => {
  const { station, startDate, endDate } = req.query;
  
  let whereClause = '1=1';
  const params = [];

  if (station) {
    whereClause += ' AND station = ?';
    params.push(station);
  }
  if (startDate) {
    whereClause += ' AND created_at >= ?';
    params.push(startDate);
  }
  if (endDate) {
    whereClause += ' AND created_at <= ?';
    params.push(endDate);
  }

  db.get(`SELECT 
    COUNT(*) as total_cases,
    SUM(CASE WHEN status = 'Open' THEN 1 ELSE 0 END) as open_cases,
    SUM(CASE WHEN status = 'Under Investigation' THEN 1 ELSE 0 END) as active_cases,
    SUM(CASE WHEN status = 'Closed' THEN 1 ELSE 0 END) as closed_cases,
    SUM(CASE WHEN priority = 'Urgent' THEN 1 ELSE 0 END) as urgent_cases
    FROM cases WHERE ${whereClause}`, 
    params,
    (err, row) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(row);
    });
});

// Cases by type
app.get('/api/stats/by-type', (req, res) => {
  db.all(`SELECT incident_type, COUNT(*) as count 
          FROM cases 
          GROUP BY incident_type 
          ORDER BY count DESC`,
    (err, rows) => {
      if (err) {
        return res.status(500).json({ error: 'Database error' });
      }
      res.json(rows);
    });
});

// ==================== USERS ====================

// Get all users
app.get('/api/users', (req, res) => {
  db.all(`SELECT id, service_number, full_name, role, station, email, phone, is_active, created_at 
          FROM users ORDER BY full_name`, 
    (err, rows) => {
      if (err) {
        console.error('Error fetching users:', err);
        return res.status(500).json({ error: 'Database error', details: err.message });
      }
      res.json(rows || []);
    });
});

// Create user
app.post('/api/users', async (req, res) => {
  const { service_number, password, full_name, role, station, email, phone } = req.body;
  
  // Validate required fields
  if (!service_number || !password || !full_name || !role) {
    return res.status(400).json({ error: 'Missing required fields: service_number, password, full_name, role' });
  }
  
  const hashedPassword = await bcrypt.hash(password, 10);
  
  db.run(`INSERT INTO users (service_number, password_hash, full_name, role, station, email, phone) 
          VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [service_number, hashedPassword, full_name, role, station, email, phone],
    function(err) {
      if (err) {
        console.error('Error creating user:', err);
        if (err.code === 'SQLITE_CONSTRAINT') {
          return res.status(400).json({ error: 'User with this service number already exists' });
        }
        return res.status(500).json({ error: 'Failed to create user', details: err.message });
      }
      res.json({ success: true, userId: this.lastID });
    });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

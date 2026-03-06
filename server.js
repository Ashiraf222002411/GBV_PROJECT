'use strict';

const express    = require('express');
const sqlite3    = require('sqlite3').verbose();
const bcrypt     = require('bcryptjs');
const helmet     = require('helmet');
const multer     = require('multer');
const rateLimit  = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const path       = require('path');
const fs         = require('fs');
const crypto     = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3001;

// ── Ensure uploads directory exists ───────────────────────────────
const UPLOADS_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });

// ── Database ───────────────────────────────────────────────────────
const db = new sqlite3.Database('./GBV_MIS.db', (err) => {
  if (err) { console.error('DB connection error:', err); process.exit(1); }
  console.log('Connected to SQLite database');
});

// Stability pragmas — run before anything else
db.serialize(() => {
  db.run('PRAGMA journal_mode = WAL');
  db.run('PRAGMA foreign_keys = ON');
  db.run('PRAGMA synchronous = NORMAL');
  db.run('PRAGMA cache_size = -16000');
});

// ── Middleware ─────────────────────────────────────────────────────
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// ── Multer (file uploads) ──────────────────────────────────────────
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(UPLOADS_DIR, String(req.params.caseId || req.params.id || 'misc'));
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    const uid = Date.now() + '-' + crypto.randomBytes(6).toString('hex');
    cb(null, uid + ext);
  }
});
const ALLOWED_MIME = [
  'image/jpeg','image/png','image/webp','application/pdf',
  'video/mp4','audio/mpeg','audio/wav',
  'application/msword',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
];
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIME.includes(file.mimetype)) cb(null, true);
    else cb(new Error(`File type not allowed: ${file.mimetype}`));
  }
});

// ── Rate Limiting ──────────────────────────────────────────────────
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' }
});

// ── Auth Middleware ────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const header = req.headers['authorization'] || '';
  const token  = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  db.get(
    `SELECT s.*, u.id as uid, u.service_number, u.full_name, u.role, u.station
     FROM sessions s JOIN users u ON s.user_id = u.id
     WHERE s.token = ? AND s.expires_at > datetime('now')`,
    [token],
    (err, row) => {
      if (err || !row) return res.status(401).json({ error: 'Invalid or expired session' });
      req.user = {
        id: row.uid, service_number: row.service_number,
        fullName: row.full_name, role: row.role, station: row.station
      };
      next();
    }
  );
}

function requireAdmin(req, res, next) {
  if (req.user && req.user.role === 'Admin') return next();
  return res.status(403).json({ error: 'Admin access required' });
}

// ── Audit Logger ───────────────────────────────────────────────────
function logAudit(userId, serviceNumber, action, targetTable, targetId, description, ip) {
  db.run(
    `INSERT INTO audit_log (user_id, service_number, action, target_table, target_id, description, ip_address)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId||null, serviceNumber||null, action, targetTable||null,
     targetId||null, description||null, ip||null],
    (err) => { if (err) console.error('Audit log error:', err.message); }
  );
}

// ── Validation helper ──────────────────────────────────────────────
function validate(req, res) {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    res.status(400).json({ error: errors.array()[0].msg, errors: errors.array() });
    return false;
  }
  return true;
}

// ── DB Initialization ──────────────────────────────────────────────
function initializeDatabase() {
  db.serialize(() => {

    db.run(`CREATE TABLE IF NOT EXISTS users (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      service_number  TEXT UNIQUE NOT NULL,
      password_hash   TEXT NOT NULL,
      full_name       TEXT NOT NULL,
      role            TEXT NOT NULL CHECK(role IN ('Admin','Investigator','Commander','Data Entry')),
      station         TEXT,
      email           TEXT,
      phone           TEXT,
      is_active       INTEGER DEFAULT 1,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login      DATETIME
    )`, err => { if (err) console.error('users:', err.message); });

    db.run(`CREATE TABLE IF NOT EXISTS sessions (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id     INTEGER NOT NULL,
      token       TEXT UNIQUE NOT NULL,
      created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at  DATETIME NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`, err => { if (err) console.error('sessions:', err.message); });

    db.run(`CREATE TABLE IF NOT EXISTS cases (
      id                     INTEGER PRIMARY KEY AUTOINCREMENT,
      case_number            TEXT UNIQUE NOT NULL,
      victim_name            TEXT NOT NULL,
      victim_age             INTEGER,
      victim_gender          TEXT,
      victim_phone           TEXT,
      victim_address         TEXT,
      incident_type          TEXT NOT NULL,
      incident_date          TEXT NOT NULL,
      incident_time          TEXT,
      incident_location      TEXT NOT NULL,
      incident_description   TEXT,
      suspect_name           TEXT DEFAULT 'Unknown',
      suspect_age            INTEGER,
      suspect_gender         TEXT,
      suspect_address        TEXT,
      relationship_to_victim TEXT,
      status                 TEXT DEFAULT 'Open' CHECK(status IN ('Open','Under Investigation','Closed','Referred')),
      priority               TEXT DEFAULT 'Normal' CHECK(priority IN ('Low','Normal','High','Urgent')),
      assigned_to            INTEGER REFERENCES users(id),
      reported_by            INTEGER REFERENCES users(id),
      station                TEXT,
      province               TEXT,
      district               TEXT,
      sector                 TEXT,
      created_at             DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at             DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, err => { if (err) console.error('cases:', err.message); });

    db.run(`CREATE TABLE IF NOT EXISTS case_updates (
      id          INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id     INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      user_id     INTEGER NOT NULL REFERENCES users(id),
      update_type TEXT NOT NULL CHECK(update_type IN ('Note','Status Change','Evidence','Interview','Action Taken')),
      description TEXT NOT NULL,
      created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, err => { if (err) console.error('case_updates:', err.message); });

    db.run(`CREATE TABLE IF NOT EXISTS investigation_logs (
      id                    INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id               INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      user_id               INTEGER NOT NULL REFERENCES users(id),
      action_taken          TEXT NOT NULL,
      evidence_ref          TEXT,
      next_action_date      TEXT,
      assigned_investigator TEXT,
      created_at            DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, err => { if (err) console.error('investigation_logs:', err.message); });

    db.run(`CREATE TABLE IF NOT EXISTS evidence (
      id                INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id           INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      evidence_type     TEXT NOT NULL,
      description       TEXT,
      collected_by      INTEGER REFERENCES users(id),
      collected_date    TEXT DEFAULT (date('now')),
      storage_location  TEXT,
      file_path         TEXT,
      original_filename TEXT,
      mime_type         TEXT,
      file_size         INTEGER,
      created_at        DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, err => { if (err) console.error('evidence:', err.message); });

    db.run(`CREATE TABLE IF NOT EXISTS referrals (
      id               INTEGER PRIMARY KEY AUTOINCREMENT,
      case_id          INTEGER NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      referral_type    TEXT NOT NULL,
      referred_to      TEXT NOT NULL,
      organization     TEXT,
      contact_person   TEXT,
      contact_phone    TEXT,
      referral_date    TEXT NOT NULL,
      referral_reason  TEXT,
      notes            TEXT,
      status           TEXT DEFAULT 'Pending' CHECK(status IN ('Pending','Active','Completed','Cancelled')),
      referred_by      INTEGER REFERENCES users(id),
      created_at       DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, err => { if (err) console.error('referrals:', err.message); });

    db.run(`CREATE TABLE IF NOT EXISTS audit_log (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP,
      user_id        INTEGER REFERENCES users(id),
      service_number TEXT,
      action         TEXT NOT NULL,
      target_table   TEXT,
      target_id      INTEGER,
      description    TEXT,
      ip_address     TEXT
    )`, err => { if (err) console.error('audit_log:', err.message); });

    // Default admin
    const pwd = bcrypt.hashSync('admin123', 10);
    db.run(`INSERT OR IGNORE INTO users (service_number, password_hash, full_name, role, station)
            VALUES ('admin', ?, 'System Administrator', 'Admin', 'HQ')`,
      [pwd], err => {
        if (err) console.error('Default admin error:', err.message);
        else     console.log('Database initialized successfully');
      });
  });
}

initializeDatabase();

// ── Schema migration: upgrade lowercase roles to Title Case ────────
db.get("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'", (err, row) => {
  if (!row || !row.sql || !row.sql.includes("'admin'")) return; // already migrated
  console.log('Running role schema migration...');
  db.serialize(() => {
    db.run('PRAGMA foreign_keys = OFF');
    // Drop sessions first (its FK will point to the renamed table after SQLite auto-update)
    db.run('DROP TABLE IF EXISTS sessions');
    db.run('ALTER TABLE users RENAME TO _users_old');
    db.run(`CREATE TABLE users (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      service_number  TEXT UNIQUE NOT NULL,
      password_hash   TEXT NOT NULL,
      full_name       TEXT NOT NULL,
      role            TEXT NOT NULL CHECK(role IN ('Admin','Investigator','Commander','Data Entry')),
      station         TEXT, email TEXT, phone TEXT,
      is_active       INTEGER DEFAULT 1,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login      DATETIME
    )`);
    db.run(`INSERT INTO users
            SELECT id, service_number, password_hash, full_name,
              CASE lower(role)
                WHEN 'admin'        THEN 'Admin'
                WHEN 'investigator' THEN 'Investigator'
                WHEN 'commander'    THEN 'Commander'
                WHEN 'data_entry'   THEN 'Data Entry'
                ELSE role
              END,
              station, email, phone, is_active, created_at, last_login
            FROM _users_old`);
    db.run('DROP TABLE _users_old');
    // Recreate sessions with correct FK
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
    db.run('PRAGMA foreign_keys = ON');
    db.run('', () => console.log('Role migration complete ✓'));
  });
});

// ── Fix sessions FK if it references a stale table ────────────────
db.get("SELECT sql FROM sqlite_master WHERE type='table' AND name='sessions'", (err, row) => {
  if (row && row.sql && !row.sql.includes('REFERENCES users(id)') && !row.sql.includes('REFERENCES "users"')) {
    console.log('Fixing sessions foreign key...');
    db.serialize(() => {
      db.run('PRAGMA foreign_keys = OFF');
      db.run('DROP TABLE IF EXISTS sessions');
      db.run(`CREATE TABLE sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token TEXT UNIQUE NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        expires_at DATETIME NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )`);
      db.run('PRAGMA foreign_keys = ON');
      db.run('', () => console.log('Sessions FK fixed ✓'));
    });
  }
});

// ── Safe static routes ─────────────────────────────────────────────
app.get('/',        (req, res) => res.sendFile(path.join(__dirname, 'GBV_MIS.html')));
app.get('/RNP.png', (req, res) => res.sendFile(path.join(__dirname, 'RNP.png')));
app.use('/uploads', requireAuth, express.static(UPLOADS_DIR));

// Clean expired sessions every hour
setInterval(() => db.run(`DELETE FROM sessions WHERE expires_at <= datetime('now')`), 3600000);

// ══════════════════════════════════════════════════════════════════
//  AUTH
// ══════════════════════════════════════════════════════════════════

app.post('/api/login', loginLimiter,
  [body('username').trim().notEmpty(), body('password').notEmpty()],
  (req, res) => {
    if (!validate(req, res)) return;
    const { username, password } = req.body;

    db.get(`SELECT * FROM users WHERE service_number = ? AND is_active = 1`, [username],
      async (err, user) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        if (!user || !(await bcrypt.compare(password, user.password_hash))) {
          logAudit(user?.id, username, 'LOGIN_FAILED', 'users', null, `Failed login: ${username}`, req.ip);
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token     = crypto.randomUUID();
        const expiresAt = new Date(Date.now() + 8 * 3600 * 1000)
                            .toISOString().replace('T',' ').slice(0,19);

        db.run(`INSERT INTO sessions (user_id, token, expires_at) VALUES (?,?,?)`,
          [user.id, token, expiresAt], function(err2) {
            if (err2) return res.status(500).json({ error: 'Session error' });
            db.run(`UPDATE users SET last_login = datetime('now') WHERE id = ?`, [user.id]);
            logAudit(user.id, user.service_number, 'LOGIN', 'users', user.id, 'Successful login', req.ip);
            res.json({
              success: true, token,
              user: { id: user.id, service_number: user.service_number,
                      fullName: user.full_name, role: user.role, station: user.station }
            });
          });
      });
  }
);

app.post('/api/logout', requireAuth, (req, res) => {
  const token = (req.headers['authorization'] || '').slice(7);
  db.run('DELETE FROM sessions WHERE token = ?', [token]);
  logAudit(req.user.id, req.user.service_number, 'LOGOUT', null, null, 'User logged out', req.ip);
  res.json({ success: true });
});

app.get('/api/auth/verify', requireAuth, (req, res) => res.json({ valid: true, user: req.user }));

// ══════════════════════════════════════════════════════════════════
//  CASES
// ══════════════════════════════════════════════════════════════════

app.get('/api/cases', requireAuth, (req, res) => {
  const { status, priority, station, search, type } = req.query;
  let where = '1=1';
  const params = [];
  if (status)   { where += ' AND c.status = ?';        params.push(status); }
  if (priority) { where += ' AND c.priority = ?';      params.push(priority); }
  if (station)  { where += ' AND c.station = ?';       params.push(station); }
  if (type)     { where += ' AND c.incident_type = ?'; params.push(type); }
  if (search) {
    where += ' AND (c.case_number LIKE ? OR c.victim_name LIKE ? OR c.district LIKE ?)';
    const s = `%${search}%`;
    params.push(s, s, s);
  }
  db.all(`SELECT c.*, a.full_name as assigned_to_name, r.full_name as reported_by_name
          FROM cases c
          LEFT JOIN users a ON c.assigned_to = a.id
          LEFT JOIN users r ON c.reported_by = r.id
          WHERE ${where} ORDER BY c.created_at DESC`,
    params, (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
});

app.get('/api/cases/:id', requireAuth, (req, res) => {
  db.get(`SELECT c.*, a.full_name as assigned_to_name, r.full_name as reported_by_name
          FROM cases c
          LEFT JOIN users a ON c.assigned_to = a.id
          LEFT JOIN users r ON c.reported_by = r.id
          WHERE c.id = ?`,
    [req.params.id], (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      if (!row) return res.status(404).json({ error: 'Case not found' });
      logAudit(req.user.id, req.user.service_number, 'CASE_VIEW', 'cases', row.id,
        `Viewed case ${row.case_number}`, req.ip);
      res.json(row);
    });
});

app.post('/api/cases', requireAuth,
  [
    body('victim_name').trim().notEmpty().withMessage('Victim name is required'),
    body('incident_type').trim().notEmpty().withMessage('Incident type is required'),
    body('incident_date').isISO8601().withMessage('Valid incident date required'),
    body('incident_location').trim().notEmpty().withMessage('Location is required'),
    body('victim_age').optional({checkFalsy:true}).isInt({min:0,max:120}).withMessage('Age must be 0-120'),
  ],
  (req, res) => {
    if (!validate(req, res)) return;
    const d = req.body;
    const yr = new Date().getFullYear();
    const caseNumber = `GBV-${yr}-${Date.now().toString().slice(-6)}`;
    const station = d.station || req.user.station || 'Unknown';

    db.run(`INSERT INTO cases (
      case_number,victim_name,victim_age,victim_gender,victim_phone,victim_address,
      incident_type,incident_date,incident_time,incident_location,incident_description,
      suspect_name,suspect_age,suspect_gender,suspect_address,relationship_to_victim,
      status,priority,assigned_to,reported_by,station,province,district,sector
    ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [caseNumber, d.victim_name, d.victim_age||null, d.victim_gender||null,
       d.victim_phone||null, d.victim_address||null,
       d.incident_type, d.incident_date, d.incident_time||null,
       d.incident_location, d.incident_description||null,
       d.suspect_name||'Unknown', d.suspect_age||null, d.suspect_gender||null,
       d.suspect_address||null, d.relationship_to_victim||null,
       d.status||'Open', d.priority||'Normal',
       d.assigned_to||null, req.user.id,
       station, d.province||null, d.district||null, d.sector||null],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to create case', detail: err.message });
        logAudit(req.user.id, req.user.service_number, 'CASE_CREATE', 'cases', this.lastID,
          `Created case ${caseNumber}`, req.ip);
        res.json({ success: true, caseId: this.lastID, caseNumber });
      });
  }
);

const ALLOWED_CASE_FIELDS = [
  'status','priority','assigned_to','incident_description','suspect_name',
  'suspect_age','suspect_gender','suspect_address','relationship_to_victim',
  'province','district','sector','victim_phone','victim_address','incident_location'
];

app.put('/api/cases/:id', requireAuth, (req, res) => {
  const safe = Object.keys(req.body).filter(k => ALLOWED_CASE_FIELDS.includes(k));
  if (!safe.length) return res.status(400).json({ error: 'No valid fields to update' });
  const fields = safe.map(k => `${k} = ?`).join(', ');
  const values = [...safe.map(k => req.body[k]), req.params.id];
  db.run(`UPDATE cases SET ${fields}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
    values, function(err) {
      if (err) return res.status(500).json({ error: 'Failed to update case' });
      logAudit(req.user.id, req.user.service_number, 'CASE_UPDATE', 'cases', req.params.id,
        `Updated: ${safe.join(', ')}`, req.ip);
      res.json({ success: true });
    });
});

// Case updates/notes
app.get('/api/cases/:id/updates', requireAuth, (req, res) => {
  db.all(`SELECT cu.*, u.full_name as user_name FROM case_updates cu
          LEFT JOIN users u ON cu.user_id = u.id
          WHERE cu.case_id = ? ORDER BY cu.created_at DESC`,
    [req.params.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
});

app.post('/api/cases/:id/updates', requireAuth,
  [body('description').trim().notEmpty().withMessage('Description is required')],
  (req, res) => {
    if (!validate(req, res)) return;
    const { update_type, description } = req.body;
    db.run(`INSERT INTO case_updates (case_id,user_id,update_type,description) VALUES (?,?,?,?)`,
      [req.params.id, req.user.id, update_type||'Note', description],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to add update' });
        res.json({ success: true, updateId: this.lastID });
      });
  }
);

// ══════════════════════════════════════════════════════════════════
//  INVESTIGATION LOGS
// ══════════════════════════════════════════════════════════════════

app.get('/api/cases/:id/investigation-logs', requireAuth, (req, res) => {
  db.all(`SELECT il.*, u.full_name as user_name FROM investigation_logs il
          LEFT JOIN users u ON il.user_id = u.id
          WHERE il.case_id = ? ORDER BY il.created_at DESC`,
    [req.params.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
});

app.post('/api/cases/:id/investigation-logs', requireAuth,
  [body('action_taken').trim().notEmpty().withMessage('Update note is required')],
  (req, res) => {
    if (!validate(req, res)) return;
    const { action_taken, evidence_ref, next_action_date, assigned_investigator } = req.body;
    db.run(`INSERT INTO investigation_logs (case_id,user_id,action_taken,evidence_ref,next_action_date,assigned_investigator)
            VALUES (?,?,?,?,?,?)`,
      [req.params.id, req.user.id, action_taken,
       evidence_ref||null, next_action_date||null, assigned_investigator||null],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to save log' });
        logAudit(req.user.id, req.user.service_number, 'INVESTIGATION_LOG', 'investigation_logs',
          this.lastID, `Added log to case ${req.params.id}`, req.ip);
        res.json({ success: true, logId: this.lastID });
      });
  }
);

// ══════════════════════════════════════════════════════════════════
//  EVIDENCE
// ══════════════════════════════════════════════════════════════════

app.get('/api/cases/:id/evidence', requireAuth, (req, res) => {
  db.all(`SELECT e.*, u.full_name as collected_by_name FROM evidence e
          LEFT JOIN users u ON e.collected_by = u.id
          WHERE e.case_id = ? ORDER BY e.created_at DESC`,
    [req.params.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
});

app.post('/api/cases/:caseId/evidence', requireAuth, upload.single('file'),
  [body('evidence_type').trim().notEmpty().withMessage('Evidence type is required')],
  (req, res) => {
    if (!validate(req, res)) return;
    const { evidence_type, description, storage_location } = req.body;
    const file    = req.file;
    const relPath = file ? path.relative(__dirname, file.path) : null;

    db.run(`INSERT INTO evidence (case_id,evidence_type,description,collected_by,
              collected_date,storage_location,file_path,original_filename,mime_type,file_size)
            VALUES (?,?,?,?,date('now'),?,?,?,?,?)`,
      [req.params.caseId, evidence_type, description||null, req.user.id,
       storage_location||null, relPath, file?.originalname||null,
       file?.mimetype||null, file?.size||null],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to save evidence' });
        logAudit(req.user.id, req.user.service_number, 'EVIDENCE_ADD', 'evidence', this.lastID,
          `Added evidence to case ${req.params.caseId}: ${file?.originalname||'no file'}`, req.ip);
        res.json({ success: true, evidenceId: this.lastID });
      });
  }
);

app.get('/api/evidence/:id/download', requireAuth, (req, res) => {
  db.get('SELECT * FROM evidence WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row || !row.file_path) return res.status(404).json({ error: 'File not found' });
    const abs = path.join(__dirname, row.file_path);
    if (!fs.existsSync(abs)) return res.status(404).json({ error: 'File missing from disk' });
    res.download(abs, row.original_filename || path.basename(abs));
  });
});

app.delete('/api/evidence/:id', requireAuth, (req, res) => {
  db.get('SELECT * FROM evidence WHERE id = ?', [req.params.id], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Evidence not found' });
    db.run('DELETE FROM evidence WHERE id = ?', [req.params.id], (err2) => {
      if (err2) return res.status(500).json({ error: 'Failed to delete' });
      if (row.file_path) fs.unlink(path.join(__dirname, row.file_path), () => {});
      logAudit(req.user.id, req.user.service_number, 'EVIDENCE_DELETE', 'evidence',
        req.params.id, `Deleted evidence ${req.params.id}`, req.ip);
      res.json({ success: true });
    });
  });
});

// ══════════════════════════════════════════════════════════════════
//  REFERRALS
// ══════════════════════════════════════════════════════════════════

app.get('/api/cases/:id/referrals', requireAuth, (req, res) => {
  db.all(`SELECT r.*, u.full_name as referred_by_name FROM referrals r
          LEFT JOIN users u ON r.referred_by = u.id
          WHERE r.case_id = ? ORDER BY r.created_at DESC`,
    [req.params.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
});

app.post('/api/cases/:id/referrals', requireAuth,
  [
    body('referral_type').trim().notEmpty().withMessage('Referral type is required'),
    body('referred_to').trim().notEmpty().withMessage('Referred to is required'),
    body('referral_date').isISO8601().withMessage('Valid date required'),
  ],
  (req, res) => {
    if (!validate(req, res)) return;
    const { referral_type, referred_to, organization, contact_person,
            contact_phone, referral_date, referral_reason, notes } = req.body;
    db.run(`INSERT INTO referrals (case_id,referral_type,referred_to,organization,
              contact_person,contact_phone,referral_date,referral_reason,notes,referred_by)
            VALUES (?,?,?,?,?,?,?,?,?,?)`,
      [req.params.id, referral_type, referred_to, organization||null,
       contact_person||null, contact_phone||null, referral_date,
       referral_reason||null, notes||null, req.user.id],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to create referral' });
        logAudit(req.user.id, req.user.service_number, 'REFERRAL_CREATE', 'referrals', this.lastID,
          `${referral_type} referral for case ${req.params.id}`, req.ip);
        res.json({ success: true, referralId: this.lastID });
      });
  }
);

app.put('/api/referrals/:id', requireAuth, (req, res) => {
  const { status } = req.body;
  if (!['Pending','Active','Completed','Cancelled'].includes(status))
    return res.status(400).json({ error: 'Invalid status' });
  db.run('UPDATE referrals SET status = ? WHERE id = ?', [status, req.params.id], (err) => {
    if (err) return res.status(500).json({ error: 'Failed to update' });
    logAudit(req.user.id, req.user.service_number, 'REFERRAL_UPDATE', 'referrals',
      req.params.id, `Referral ${req.params.id} → ${status}`, req.ip);
    res.json({ success: true });
  });
});

// ══════════════════════════════════════════════════════════════════
//  STATS & REPORTS
// ══════════════════════════════════════════════════════════════════

app.get('/api/stats', requireAuth, (req, res) => {
  const { station, startDate, endDate } = req.query;
  let where = '1=1';
  const params = [];
  if (station)   { where += ' AND station = ?';               params.push(station); }
  if (startDate) { where += ' AND created_at >= ?';           params.push(startDate); }
  if (endDate)   { where += ' AND created_at <= ?';           params.push(endDate + ' 23:59:59'); }

  db.get(`SELECT
    COUNT(*) as total_cases,
    SUM(CASE WHEN status='Open' THEN 1 ELSE 0 END) as open_cases,
    SUM(CASE WHEN status='Under Investigation' THEN 1 ELSE 0 END) as active_cases,
    SUM(CASE WHEN status='Closed' THEN 1 ELSE 0 END) as closed_cases,
    SUM(CASE WHEN status='Referred' THEN 1 ELSE 0 END) as referred_cases,
    SUM(CASE WHEN priority='Urgent' THEN 1 ELSE 0 END) as urgent_cases
    FROM cases WHERE ${where}`, params,
    (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(row);
    });
});

app.get('/api/stats/by-type', requireAuth, (req, res) => {
  const { from, to } = req.query;
  let where = '1=1';
  const params = [];
  if (from) { where += ' AND incident_date >= ?'; params.push(from); }
  if (to)   { where += ' AND incident_date <= ?'; params.push(to); }
  db.all(`SELECT incident_type, COUNT(*) as count FROM cases WHERE ${where}
          GROUP BY incident_type ORDER BY count DESC`, params,
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
});

app.get('/api/stats/monthly', requireAuth, (req, res) => {
  const year = req.query.year || new Date().getFullYear();
  db.all(`SELECT strftime('%m', incident_date) as month, COUNT(*) as count
          FROM cases WHERE strftime('%Y', incident_date) = ?
          GROUP BY month ORDER BY month`,
    [String(year)], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
});

app.get('/api/reports/summary', requireAuth, (req, res) => {
  const { from, to, province, type } = req.query;
  let where = '1=1';
  const params = [];
  if (from)     { where += ' AND incident_date >= ?'; params.push(from); }
  if (to)       { where += ' AND incident_date <= ?'; params.push(to); }
  if (province) { where += ' AND province = ?';       params.push(province); }
  if (type)     { where += ' AND incident_type = ?';  params.push(type); }

  db.get(`SELECT
    COUNT(*) as total,
    SUM(CASE WHEN status='Open' THEN 1 ELSE 0 END) as open_cases,
    SUM(CASE WHEN status='Under Investigation' THEN 1 ELSE 0 END) as active_cases,
    SUM(CASE WHEN status='Closed' THEN 1 ELSE 0 END) as closed_cases,
    SUM(CASE WHEN status='Referred' THEN 1 ELSE 0 END) as referred_cases,
    SUM(CASE WHEN priority='Urgent' THEN 1 ELSE 0 END) as urgent_cases,
    COUNT(DISTINCT district) as districts_affected
    FROM cases WHERE ${where}`, params,
    (err, summary) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      db.all(`SELECT incident_type, COUNT(*) as count FROM cases WHERE ${where}
              GROUP BY incident_type ORDER BY count DESC`, params,
        (err2, byType) => {
          if (err2) return res.status(500).json({ error: 'Database error' });
          logAudit(req.user.id, req.user.service_number, 'REPORT_VIEW', null, null,
            `Report generated (${from||'all'} to ${to||'all'})`, req.ip);
          res.json({ summary, byType });
        });
    });
});

// ══════════════════════════════════════════════════════════════════
//  SURVIVORS & SUSPECTS
// ══════════════════════════════════════════════════════════════════

app.get('/api/survivors', requireAuth, (req, res) => {
  db.all(`SELECT c.id, c.case_number, c.victim_gender, c.victim_age,
            c.district, c.province, c.status, c.priority, c.created_at,
            u.full_name as assigned_to_name
          FROM cases c LEFT JOIN users u ON c.assigned_to = u.id
          ORDER BY c.created_at DESC`, [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
});

app.get('/api/suspects', requireAuth, (req, res) => {
  db.all(`SELECT id, case_number, suspect_name, suspect_age, suspect_gender,
            suspect_address, relationship_to_victim, status, created_at
          FROM cases
          WHERE suspect_name IS NOT NULL AND suspect_name != '' AND suspect_name != 'Unknown'
          ORDER BY created_at DESC`, [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
});

// ══════════════════════════════════════════════════════════════════
//  AUDIT LOG
// ══════════════════════════════════════════════════════════════════

app.get('/api/audit', requireAuth, requireAdmin, (req, res) => {
  const { action, from, to, limit = 100, offset = 0 } = req.query;
  let where = '1=1';
  const params = [];
  if (action) { where += ' AND al.action = ?';        params.push(action); }
  if (from)   { where += ' AND al.timestamp >= ?';    params.push(from); }
  if (to)     { where += ' AND al.timestamp <= ?';    params.push(to + ' 23:59:59'); }

  db.all(`SELECT al.*, u.full_name FROM audit_log al
          LEFT JOIN users u ON al.user_id = u.id
          WHERE ${where} ORDER BY al.timestamp DESC
          LIMIT ? OFFSET ?`,
    [...params, parseInt(limit), parseInt(offset)],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      db.get(`SELECT COUNT(*) as total FROM audit_log WHERE ${where}`, params,
        (e, cnt) => res.json({ logs: rows, total: cnt?.total || 0 }));
    });
});

// ══════════════════════════════════════════════════════════════════
//  USERS
// ══════════════════════════════════════════════════════════════════

app.get('/api/users', requireAuth, (req, res) => {
  db.all(`SELECT id, service_number, full_name, role, station, email, phone,
            is_active, created_at, last_login FROM users ORDER BY full_name`,
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
});

app.post('/api/users', requireAuth, requireAdmin,
  [
    body('service_number').trim().notEmpty().withMessage('Service number is required'),
    body('password').isLength({min:6}).withMessage('Password must be at least 6 characters'),
    body('full_name').trim().notEmpty().withMessage('Full name is required'),
    body('role').isIn(['Admin','Investigator','Commander','Data Entry']).withMessage('Invalid role'),
  ],
  async (req, res) => {
    if (!validate(req, res)) return;
    const { service_number, password, full_name, role, station, email, phone } = req.body;
    const hash = await bcrypt.hash(password, 10);
    db.run(`INSERT INTO users (service_number,password_hash,full_name,role,station,email,phone)
            VALUES (?,?,?,?,?,?,?)`,
      [service_number, hash, full_name, role, station||null, email||null, phone||null],
      function(err) {
        if (err) {
          if (err.code === 'SQLITE_CONSTRAINT' && err.message.includes('UNIQUE'))
            return res.status(400).json({ error: 'User with this service number already exists' });
          if (err.code === 'SQLITE_CONSTRAINT')
            return res.status(400).json({ error: 'Invalid role. Must be Admin, Investigator, Commander, or Data Entry' });
          return res.status(500).json({ error: 'Failed to create user' });
        }
        logAudit(req.user.id, req.user.service_number, 'USER_CREATE', 'users', this.lastID,
          `Created user ${service_number} (${role})`, req.ip);
        res.json({ success: true, userId: this.lastID });
      });
  }
);

app.put('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const ALLOWED = ['full_name','role','station','email','phone'];
  const safe = Object.keys(req.body).filter(k => ALLOWED.includes(k));
  if (!safe.length) return res.status(400).json({ error: 'No valid fields' });
  const fields = safe.map(k => `${k} = ?`).join(', ');
  const values = [...safe.map(k => req.body[k]), req.params.id];
  db.run(`UPDATE users SET ${fields} WHERE id = ?`, values, function(err) {
    if (err) return res.status(500).json({ error: 'Failed to update user' });
    logAudit(req.user.id, req.user.service_number, 'USER_UPDATE', 'users',
      req.params.id, `Updated user ${req.params.id}`, req.ip);
    res.json({ success: true });
  });
});

app.post('/api/users/:id/toggle-active', requireAuth, requireAdmin, (req, res) => {
  db.run('UPDATE users SET is_active = CASE WHEN is_active=1 THEN 0 ELSE 1 END WHERE id = ?',
    [req.params.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to toggle' });
      logAudit(req.user.id, req.user.service_number, 'USER_TOGGLE', 'users',
        req.params.id, `Toggled user ${req.params.id}`, req.ip);
      res.json({ success: true });
    });
});

// ── Global error handler ───────────────────────────────────────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, _next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE')
      return res.status(400).json({ error: 'File too large. Maximum 10MB allowed.' });
    return res.status(400).json({ error: err.message });
  }
  if (err.message?.includes('File type not allowed'))
    return res.status(400).json({ error: err.message });
  console.error('Server error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on port ${PORT}`);
});

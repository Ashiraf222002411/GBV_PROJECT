'use strict';

require('dotenv').config();

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

// ── Notification Helpers ───────────────────────────────────────────
function createNotification(userId, title, message, type, caseId) {
  db.run(
    `INSERT INTO notifications (user_id, title, message, type, case_id) VALUES (?,?,?,?,?)`,
    [userId, title, message, type || 'info', caseId || null],
    err => { if (err) console.error('Notification error:', err.message); }
  );
}

function notifyAdminsCommanders(title, message, type, caseId) {
  db.all(`SELECT id FROM users WHERE role IN ('Admin','Commander') AND is_active = 1`, (err, rows) => {
    if (err || !rows) return;
    rows.forEach(u => createNotification(u.id, title, message, type, caseId));
  });
}

// ── Stale Case Delay Check (runs every 6 hours) ────────────────────
function checkStaleCases() {
  db.all(`
    SELECT c.id, c.case_number, c.incident_type, c.assigned_to,
           u.full_name as officer_name,
           MAX(cu.created_at) as last_update
    FROM cases c
    LEFT JOIN users u ON c.assigned_to = u.id
    LEFT JOIN case_updates cu ON cu.case_id = c.id
    WHERE c.status IN ('Open','Under Investigation')
      AND c.assigned_to IS NOT NULL
    GROUP BY c.id
    HAVING last_update IS NULL OR last_update < datetime('now','-7 days')
  `, (err, rows) => {
    if (err || !rows || rows.length === 0) return;
    rows.forEach(c => {
      const msg = `Case ${c.case_number} (${c.incident_type}) assigned to ${c.officer_name || 'Unknown'} has had no updates for over 7 days. Please follow up.`;
      notifyAdminsCommanders('⚠️ Stale Case Alert', msg, 'alert', c.id);
      console.log(`Stale case alert sent for ${c.case_number}`);
    });
  });
}
setInterval(checkStaleCases, 6 * 60 * 60 * 1000); // every 6 hours
setTimeout(checkStaleCases, 10000);                // also run 10s after startup

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
      role            TEXT NOT NULL CHECK(role IN ('Admin','Investigator','Commander','Police Officer','Medical Entry Officer')),
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

    db.run(`CREATE TABLE IF NOT EXISTS notifications (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      title      TEXT NOT NULL,
      message    TEXT NOT NULL,
      type       TEXT DEFAULT 'info' CHECK(type IN ('info','assignment','update','alert')),
      case_id    INTEGER REFERENCES cases(id) ON DELETE SET NULL,
      is_read    INTEGER DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, err => { if (err) console.error('notifications:', err.message); });

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

// ── Seed Data ──────────────────────────────────────────────────────
function seedDatabase() {
  db.get('SELECT COUNT(*) as cnt FROM cases', (err, row) => {
    if (err || (row && row.cnt > 0)) return; // skip if data already exists

    console.log('Seeding database with sample data...');

    const rwLocations = [
      { province: 'Kigali City',       district: 'Gasabo',     sector: 'Kimironko',    station: 'Kimironko PS' },
      { province: 'Kigali City',       district: 'Gasabo',     sector: 'Remera',       station: 'Remera PS' },
      { province: 'Kigali City',       district: 'Gasabo',     sector: 'Kacyiru',      station: 'Kacyiru PS' },
      { province: 'Kigali City',       district: 'Gasabo',     sector: 'Gisozi',       station: 'Gisozi PS' },
      { province: 'Kigali City',       district: 'Kicukiro',   sector: 'Niboye',       station: 'Kicukiro PS' },
      { province: 'Kigali City',       district: 'Kicukiro',   sector: 'Kagarama',     station: 'Kagarama PS' },
      { province: 'Kigali City',       district: 'Kicukiro',   sector: 'Gatenga',      station: 'Gatenga PS' },
      { province: 'Kigali City',       district: 'Nyarugenge', sector: 'Muhima',       station: 'Muhima PS' },
      { province: 'Kigali City',       district: 'Nyarugenge', sector: 'Nyamirambo',   station: 'Nyamirambo PS' },
      { province: 'Kigali City',       district: 'Nyarugenge', sector: 'Rwezamenyo',   station: 'Rwezamenyo PS' },
      { province: 'Northern Province', district: 'Musanze',    sector: 'Muhoza',       station: 'Musanze PS' },
      { province: 'Northern Province', district: 'Musanze',    sector: 'Cyuve',        station: 'Musanze PS' },
      { province: 'Northern Province', district: 'Gicumbi',    sector: 'Byumba',       station: 'Gicumbi PS' },
      { province: 'Northern Province', district: 'Gicumbi',    sector: 'Kaniga',       station: 'Gicumbi PS' },
      { province: 'Northern Province', district: 'Burera',     sector: 'Cyanika',      station: 'Burera PS' },
      { province: 'Northern Province', district: 'Gakenke',    sector: 'Gakenke',      station: 'Gakenke PS' },
      { province: 'Northern Province', district: 'Rulindo',    sector: 'Base',         station: 'Rulindo PS' },
      { province: 'Southern Province', district: 'Huye',       sector: 'Ngoma',        station: 'Huye PS' },
      { province: 'Southern Province', district: 'Huye',       sector: 'Tumba',        station: 'Huye PS' },
      { province: 'Southern Province', district: 'Muhanga',    sector: 'Muhanga',      station: 'Muhanga PS' },
      { province: 'Southern Province', district: 'Nyanza',     sector: 'Nyanza',       station: 'Nyanza PS' },
      { province: 'Southern Province', district: 'Ruhango',    sector: 'Ruhango',      station: 'Ruhango PS' },
      { province: 'Southern Province', district: 'Kamonyi',    sector: 'Kamonyi',      station: 'Kamonyi PS' },
      { province: 'Southern Province', district: 'Nyamagabe',  sector: 'Kitabi',       station: 'Nyamagabe PS' },
      { province: 'Southern Province', district: 'Gisagara',   sector: 'Gisagara',     station: 'Gisagara PS' },
      { province: 'Eastern Province',  district: 'Rwamagana',  sector: 'Rwamagana',    station: 'Rwamagana PS' },
      { province: 'Eastern Province',  district: 'Kayonza',    sector: 'Mukarange',    station: 'Kayonza PS' },
      { province: 'Eastern Province',  district: 'Bugesera',   sector: 'Nyamata',      station: 'Bugesera PS' },
      { province: 'Eastern Province',  district: 'Nyagatare',  sector: 'Nyagatare',    station: 'Nyagatare PS' },
      { province: 'Eastern Province',  district: 'Gatsibo',    sector: 'Kiziguro',     station: 'Gatsibo PS' },
      { province: 'Eastern Province',  district: 'Kirehe',     sector: 'Kirehe',       station: 'Kirehe PS' },
      { province: 'Eastern Province',  district: 'Ngoma',      sector: 'Kibungo',      station: 'Ngoma PS' },
      { province: 'Western Province',  district: 'Rubavu',     sector: 'Gisenyi',      station: 'Rubavu PS' },
      { province: 'Western Province',  district: 'Rubavu',     sector: 'Rugerero',     station: 'Rubavu PS' },
      { province: 'Western Province',  district: 'Rusizi',     sector: 'Kamembe',      station: 'Rusizi PS' },
      { province: 'Western Province',  district: 'Karongi',    sector: 'Kibuye',       station: 'Karongi PS' },
      { province: 'Western Province',  district: 'Nyabihu',    sector: 'Kintobo',      station: 'Nyabihu PS' },
      { province: 'Western Province',  district: 'Ngororero',  sector: 'Ngororero',    station: 'Ngororero PS' },
      { province: 'Western Province',  district: 'Nyamasheke', sector: 'Shangi',       station: 'Nyamasheke PS' },
      { province: 'Western Province',  district: 'Rutsiro',    sector: 'Murunda',      station: 'Rutsiro PS' },
    ];

    const femaleNames = [
      'Mukamana Chantal','Uwimana Marie','Umubyeyi Esperance','Mukankusi Beatrice',
      'Uwineza Solange','Nyirahabimana Olive','Mukagakwandi Josephine','Uwase Vestine',
      'Mukamazimpaka Claudine','Akimana Diane','Nyiraneza Alphonsine','Mukashyaka Valerie',
      'Uwingabiye Angele','Mukamusoni Immaculee','Nyirabageni Annette','Mukamuganga Cecile',
      'Uwera Ange','Murekatete Florentine','Mukaremera Therese','Nyiramahoro Gaudence',
      'Mukantaganzwa Providance','Uwantege Julienne','Mukandekezi Rose','Nyirakamana Scholastique',
      'Mukagatare Antoinette','Uwimana Felicite','Nyirabagenzi Constance','Mukarukundo Leontine',
      'Umurungi Pascasie','Mukashema Domitille','Nyirarukundo Suzanne','Mukabatware Justine',
      'Uwamariya Bernadette','Mukazitoni Prisca','Nyirabeza Agnes','Mukantwali Mathilde',
      'Uwizeye Solange','Mukarutesi Theophile','Nyirankundiye Goretti','Mukamuhoza Francoise',
      'Uwamahoro Generose','Mukasakindi Perpetue','Nyiramugisha Faustine','Mukarwego Donata',
      'Uwineza Clarisse','Mukamukasa Julienne','Nyirabagabo Valentina','Mukankineza Annunciata',
      'Uwingabire Georgette','Mukaneza Denise','Nyirabagenzi Therese','Mukamusoni Odette',
      'Uwimana Consolee','Mukagatare Monique','Nyiraneza Clementine','Mukamana Jacqueline',
      'Uwacu Liberata','Mukarwamo Emeritha','Nyirabageni Marceline','Mukamuhirwa Modeste',
    ];

    const maleNames = [
      'Habimana Jean','Nkurunziza Pierre','Bizimana Emmanuel','Ndayishimiye Alexis',
      'Niyonzima Sylvestre','Nzeyimana Celestin','Hakizimana Callixte','Nizeyimana Innocent',
      'Habyarimana Felix','Nshimiyimana Alexis','Rurangwa Eric','Kaberuka Patrick',
      'Ndizeye Claude','Muhayimana Theogene','Ntakirutimana Edouard','Kayitare Frederic',
      'Bizumuremyi Augustin','Bazimaziki Vincent','Tuyishime Pacifique','Nzamwita Damien',
      'Mugabo Samuel','Hakizayo Faustin','Ntibituruki Juvénal','Sekamonyo Gaspard',
      'Musabyimana Jean-Marie','Kamanzi Fidele','Nshimiyumukiza Aloys','Uwimana Bosco',
      'Ndikumana Desire','Kayiranga Modeste','Muvunyi Augustin','Twagirayezu Leon',
      'Bizimungu Donat','Gatera Olivier','Rukundo Mathieu','Kagabo Theodore',
      'Niyomugabo Felicien','Hagenimana Jerome','Nzabanita Protais','Sezikeye Samuel',
    ];

    const incidentTypes = [
      'Domestic Violence','Domestic Violence','Domestic Violence',
      'Sexual Violence','Sexual Violence',
      'Child Abuse',
      'Stalking/Harassment',
      'Forced Marriage',
      'Economic Abuse',
    ];

    const statuses   = ['Open','Open','Under Investigation','Under Investigation','Closed','Referred'];
    const priorities = ['Low','Normal','Normal','High','Urgent'];

    const descriptions = {
      'Domestic Violence': [
        'Survivor reported repeated physical assault by spouse over several months. Injuries include bruises on arms and face.',
        'Victim was beaten by partner after a domestic dispute. Neighbours called police after hearing screams.',
        'Survivor presented with injuries consistent with blunt force trauma. Reported ongoing violence in the home.',
        'Victim fled the marital home after sustained abuse. Temporary shelter arranged through ISANGE ONE STOP Centre.',
      ],
      'Sexual Violence': [
        'Survivor reported sexual assault by an acquaintance. Medical examination conducted at district hospital.',
        'Victim reported rape incident. Forensic evidence collected. Survivor referred for psychosocial support.',
        'Minor survivor reported sexual abuse. Case referred to Child Protection Unit and prosecution.',
        'Survivor disclosed assault during routine community outreach. Case opened retrospectively.',
      ],
      'Child Abuse': [
        'Child presented with unexplained injuries. Teacher reported suspected abuse to local authorities.',
        'Child disclosed physical and emotional abuse by guardian. Removed from home pending investigation.',
        'School counsellor reported concerning behaviour. Investigation revealed sustained neglect.',
        'Child victim referred by MIGEPROF partner organisation. CPS engaged.',
      ],
      'Stalking/Harassment': [
        'Victim reported persistent unwanted contact and threats from former partner.',
        'Survivor received threatening messages and was followed to workplace. Protective order sought.',
        'Victim reported being surveilled at home and work over three-week period.',
      ],
      'Forced Marriage': [
        'Minor girl reported being coerced into marriage by family. Rescue and shelter coordinated.',
        'Survivor escaped forced marriage arrangement and sought police protection.',
        'Community leader reported suspected forced marriage of a minor in rural area.',
      ],
      'Economic Abuse': [
        'Survivor reported systematic deprivation of finances and employment sabotage by partner.',
        'Victim denied access to household income and property documents. Legal aid referred.',
        'Survivor reported eviction from marital property by spouse without legal process.',
      ],
    };

    const relationships = ['Spouse','Former Partner','Parent','Relative','Neighbour','Employer','Acquaintance','Unknown'];

    function randItem(arr) { return arr[Math.floor(Math.random() * arr.length)]; }
    function randInt(min, max) { return Math.floor(Math.random() * (max - min + 1)) + min; }
    function pastDate(maxDaysAgo) {
      const d = new Date();
      d.setDate(d.getDate() - randInt(0, maxDaysAgo));
      return d.toISOString().slice(0, 10);
    }

    // Insert seed users first, then cases
    const seedUsers = [
      { sn: 'RNP-0001', name: 'Insp. Kagabo Theodore',   role: 'Investigator',  station: 'Remera PS' },
      { sn: 'RNP-0002', name: 'Insp. Uwimana Solange',   role: 'Investigator',  station: 'Kicukiro PS' },
      { sn: 'RNP-0003', name: 'Insp. Niyonzima Eric',    role: 'Investigator',  station: 'Musanze PS' },
      { sn: 'RNP-0004', name: 'Insp. Mukamana Rose',     role: 'Investigator',  station: 'Huye PS' },
      { sn: 'RNP-0005', name: 'Insp. Habimana Claude',   role: 'Investigator',  station: 'Rubavu PS' },
      { sn: 'RNP-0006', name: 'Insp. Uwineza Diane',     role: 'Investigator',  station: 'Rwamagana PS' },
      { sn: 'RNP-0010', name: 'Supt. Rurangwa Jean',     role: 'Commander',     station: 'Kigali City HQ' },
      { sn: 'RNP-0011', name: 'Supt. Nyiraneza Alice',   role: 'Commander',     station: 'Northern Province HQ' },
      { sn: 'RNP-0012', name: 'Supt. Bizimana Paul',     role: 'Commander',     station: 'Southern Province HQ' },
      { sn: 'RNP-0020', name: 'Cst. Uwase Claudine',     role: 'Medical Entry Officer',    station: 'Kimironko PS' },
      { sn: 'RNP-0021', name: 'Cst. Ndizeye Patrick',    role: 'Medical Entry Officer',    station: 'Musanze PS' },
    ];

    const defaultPwd = bcrypt.hashSync('Rnp@2024', 10);
    let userIds = {};

    db.serialize(() => {
      // Insert seed users
      const userStmt = db.prepare(
        `INSERT OR IGNORE INTO users (service_number, password_hash, full_name, role, station)
         VALUES (?, ?, ?, ?, ?)`
      );
      for (const u of seedUsers) {
        userStmt.run([u.sn, defaultPwd, u.name, u.role, u.station]);
      }
      userStmt.finalize();

      // Fetch admin + seed investigator IDs for assigning cases
      db.all(`SELECT id, service_number, role FROM users`, (err2, users) => {
        if (err2) { console.error('Seed: could not fetch users'); return; }

        const investigators = users.filter(u => u.role === 'Investigator').map(u => u.id);
        const admins        = users.filter(u => u.role === 'Admin').map(u => u.id);
        const allStaff      = [...investigators, ...admins];

        // Build 120 cases
        const caseStmt = db.prepare(`INSERT OR IGNORE INTO cases
          (case_number, victim_name, victim_age, victim_gender, victim_phone, victim_address,
           incident_type, incident_date, incident_time, incident_location, incident_description,
           suspect_name, suspect_age, suspect_gender, relationship_to_victim,
           status, priority, assigned_to, reported_by, station, province, district, sector)
          VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);

        const year = new Date().getFullYear();
        for (let i = 1; i <= 120; i++) {
          const loc        = randItem(rwLocations);
          const type       = randItem(incidentTypes);
          const descArr    = descriptions[type];
          const victimName = randItem(femaleNames);
          const suspectName= Math.random() > 0.15 ? randItem(maleNames) : 'Unknown';
          const caseNum    = `GBV-${year}-${String(i).padStart(6, '0')}`;
          const date       = pastDate(540); // up to ~18 months ago
          const time       = `${String(randInt(6,22)).padStart(2,'0')}:${randInt(0,1)*30 === 0 ? '00':'30'}`;
          const status     = randItem(statuses);
          const priority   = randItem(priorities);
          const assignedTo = allStaff.length ? randItem(allStaff) : null;
          const reportedBy = allStaff.length ? randItem(allStaff) : null;

          caseStmt.run([
            caseNum,
            victimName,
            randInt(15, 55),
            'Female',
            `+2507${randInt(80000000,99999999)}`,
            `${loc.sector}, ${loc.district}`,
            type,
            date,
            time,
            `${loc.sector}, ${loc.district}`,
            randItem(descArr),
            suspectName,
            suspectName !== 'Unknown' ? randInt(20, 60) : null,
            suspectName !== 'Unknown' ? 'Male' : null,
            randItem(relationships),
            status,
            priority,
            assignedTo,
            reportedBy,
            loc.station,
            loc.province,
            loc.district,
            loc.sector,
          ]);
        }

        caseStmt.finalize(() => {
          console.log('Seed complete: 120 sample cases and 11 users inserted ✓');
        });
      });
    });
  });
}

// Run seed after a short delay to allow schema init to complete
setTimeout(seedDatabase, 1500);

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
      role            TEXT NOT NULL CHECK(role IN ('Admin','Investigator','Commander','Police Officer','Medical Entry Officer')),
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
                WHEN 'data_entry'   THEN 'Medical Entry Officer'
                WHEN 'data entry'   THEN 'Medical Entry Officer'
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

// ── Migration: rename 'Data Entry' → 'Medical Entry Officer' and add 'Police Officer' ──
db.get("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'", (err, row) => {
  if (!row || !row.sql) return;
  const needsRoleUpgrade = row.sql.includes("'Data Entry'") || !row.sql.includes("'Police Officer'");
  if (!needsRoleUpgrade) return;
  console.log('Running role rename migration (Data Entry → Medical Entry Officer)...');
  db.serialize(() => {
    db.run('PRAGMA foreign_keys = OFF');
    db.run('DROP TABLE IF EXISTS sessions'); // drop before rename to avoid dangling FK
    db.run('ALTER TABLE users RENAME TO _users_pre_role');
    db.run(`CREATE TABLE users (
      id              INTEGER PRIMARY KEY AUTOINCREMENT,
      service_number  TEXT UNIQUE NOT NULL,
      password_hash   TEXT NOT NULL,
      full_name       TEXT NOT NULL,
      role            TEXT NOT NULL CHECK(role IN ('Admin','Investigator','Commander','Police Officer','Medical Entry Officer')),
      station         TEXT, email TEXT, phone TEXT,
      is_active       INTEGER DEFAULT 1,
      created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
      last_login      DATETIME
    )`);
    db.run(`INSERT INTO users
            SELECT id, service_number, password_hash, full_name,
              CASE role
                WHEN 'Data Entry' THEN 'Medical Entry Officer'
                WHEN 'Officer'    THEN 'Police Officer'
                ELSE role
              END,
              station, email, phone, is_active, created_at, last_login
            FROM _users_pre_role`);
    db.run('DROP TABLE _users_pre_role');
    db.run(`CREATE TABLE IF NOT EXISTS sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )`);
    // Recreate audit_log with corrected FK
    db.run(`CREATE TABLE IF NOT EXISTS _audit_backup AS SELECT * FROM audit_log`);
    db.run(`DROP TABLE IF EXISTS audit_log`);
    db.run(`CREATE TABLE audit_log (
      id             INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp      DATETIME DEFAULT CURRENT_TIMESTAMP,
      user_id        INTEGER REFERENCES users(id),
      service_number TEXT,
      action         TEXT NOT NULL,
      target_table   TEXT,
      target_id      INTEGER,
      description    TEXT,
      ip_address     TEXT
    )`);
    db.run(`INSERT OR IGNORE INTO audit_log SELECT * FROM _audit_backup`);
    db.run(`DROP TABLE IF EXISTS _audit_backup`);
    db.run('PRAGMA foreign_keys = ON');
    db.run('', () => console.log('Role rename migration complete ✓'));
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
app.get('/',          (req, res) => res.sendFile(path.join(__dirname, 'homepage.html')));
app.get('/app',       (req, res) => res.sendFile(path.join(__dirname, 'GBV_MIS.html')));
app.get('/RNP.png',   (req, res) => res.sendFile(path.join(__dirname, 'RNP.png')));
app.use('/images',    express.static(path.join(__dirname, 'images')));
app.use('/uploads',   requireAuth, express.static(UPLOADS_DIR));

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
        const newId = this.lastID;
        logAudit(req.user.id, req.user.service_number, 'CASE_CREATE', 'cases', newId,
          `Created case ${caseNumber}`, req.ip);
        // Notify all Admins & Commanders of new case
        const notifMsg = `New ${d.incident_type} case ${caseNumber} registered by ${req.user.fullName} (${req.user.station || 'Unknown Station'}).`;
        notifyAdminsCommanders('📋 New Case Registered', notifMsg, 'info', newId);
        // If a specific officer was assigned at registration, notify them too
        if (d.assigned_to) {
          createNotification(d.assigned_to,
            '📌 Case Assigned to You',
            `Case ${caseNumber} (${d.incident_type}) has been assigned to you by ${req.user.fullName}.`,
            'assignment', newId);
        }
        res.json({ success: true, caseId: newId, caseNumber });
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

  const caseId = parseInt(req.params.id);

  // Fetch existing case first so we can detect assignment changes
  db.get(`SELECT c.*, u.full_name as current_officer FROM cases c LEFT JOIN users u ON c.assigned_to = u.id WHERE c.id = ?`, [caseId], (fetchErr, existing) => {
    if (fetchErr || !existing) return res.status(404).json({ error: 'Case not found' });

    const fields = safe.map(k => `${k} = ?`).join(', ');
    const values = [...safe.map(k => req.body[k]), caseId];

    db.run(`UPDATE cases SET ${fields}, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
      values, function(err) {
        if (err) return res.status(500).json({ error: 'Failed to update case' });
        logAudit(req.user.id, req.user.service_number, 'CASE_UPDATE', 'cases', caseId,
          `Updated: ${safe.join(', ')}`, req.ip);

        const newAssignedTo = req.body.assigned_to != null ? parseInt(req.body.assigned_to) || null : undefined;

        // If assigned_to changed, notify new officer + notify admins/commanders
        if (newAssignedTo !== undefined && newAssignedTo !== existing.assigned_to) {
          if (newAssignedTo) {
            createNotification(newAssignedTo,
              '📌 Case Assigned to You',
              `Case ${existing.case_number} (${existing.incident_type}) has been assigned to you by ${req.user.fullName}.`,
              'assignment', caseId);
          }
          const changedBy = req.user.fullName;
          notifyAdminsCommanders(
            '🔄 Case Reassigned',
            `Case ${existing.case_number} has been reassigned by ${changedBy}.`,
            'info', caseId
          );
        }

        // Notify admins/commanders of status or priority changes
        if (req.body.status && req.body.status !== existing.status) {
          notifyAdminsCommanders(
            '📊 Case Status Updated',
            `Case ${existing.case_number} status changed from "${existing.status}" to "${req.body.status}" by ${req.user.fullName}.`,
            'update', caseId
          );
        }

        res.json({ success: true });
      });
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
    const caseId = parseInt(req.params.id);
    db.run(`INSERT INTO case_updates (case_id,user_id,update_type,description) VALUES (?,?,?,?)`,
      [caseId, req.user.id, update_type||'Note', description],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to add update' });
        // Notify admins/commanders of the progress update
        db.get(`SELECT case_number, incident_type, assigned_to FROM cases WHERE id = ?`, [caseId], (e, c) => {
          if (e || !c) return;
          const title = `📝 Case Update: ${c.case_number}`;
          const msg   = `${req.user.fullName} added a "${update_type||'Note'}" update on case ${c.case_number} (${c.incident_type}): "${description.slice(0,120)}${description.length > 120 ? '…' : ''}"`;
          notifyAdminsCommanders(title, msg, 'update', caseId);
          // Also notify the assigned officer if different from the person making the update
          if (c.assigned_to && c.assigned_to !== req.user.id) {
            createNotification(c.assigned_to, title,
              `A new update was added to your case ${c.case_number} by ${req.user.fullName}.`,
              'update', caseId);
          }
        });
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
  db.all(`SELECT c.id, c.case_number, c.victim_name, c.victim_gender, c.victim_age,
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
//  NOTIFICATIONS
// ══════════════════════════════════════════════════════════════════

// Get notifications for current user (latest 50)
app.get('/api/notifications', requireAuth, (req, res) => {
  db.all(`SELECT n.*, c.case_number FROM notifications n
          LEFT JOIN cases c ON n.case_id = c.id
          WHERE n.user_id = ?
          ORDER BY n.created_at DESC LIMIT 50`,
    [req.user.id], (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    });
});

// Unread count
app.get('/api/notifications/count', requireAuth, (req, res) => {
  db.get(`SELECT COUNT(*) as count FROM notifications WHERE user_id = ? AND is_read = 0`,
    [req.user.id], (err, row) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ count: row ? row.count : 0 });
    });
});

// Mark single notification as read
app.put('/api/notifications/:id/read', requireAuth, (req, res) => {
  db.run(`UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?`,
    [req.params.id, req.user.id], err => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    });
});

// Mark all as read
app.put('/api/notifications/read-all', requireAuth, (req, res) => {
  db.run(`UPDATE notifications SET is_read = 1 WHERE user_id = ?`,
    [req.user.id], err => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json({ success: true });
    });
});

// ══════════════════════════════════════════════════════════════════
//  USERS
// ══════════════════════════════════════════════════════════════════

app.get('/api/users', requireAuth, (req, res) => {
  const role = req.user.role;
  // Admin & Commander see all users; others see only themselves (for assignment dropdown)
  if (role === 'Admin' || role === 'Commander') {
    db.all(`SELECT id, service_number, full_name, role, station, email, phone,
              is_active, created_at, last_login FROM users ORDER BY full_name`,
      (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
      });
  } else {
    // Investigators / Police Officers / Medical Entry Officers only see themselves
    db.all(`SELECT id, service_number, full_name, role, station, email, phone,
              is_active, created_at, last_login FROM users WHERE id = ? ORDER BY full_name`,
      [req.user.id], (err, rows) => {
        if (err) return res.status(500).json({ error: 'Database error' });
        res.json(rows);
      });
  }
});

app.post('/api/users', requireAuth, requireAdmin,
  [
    body('service_number').trim().notEmpty().withMessage('Service number is required'),
    body('password').isLength({min:6}).withMessage('Password must be at least 6 characters'),
    body('full_name').trim().notEmpty().withMessage('Full name is required')
      .matches(/^[A-Za-z\s]+$/).withMessage('Full name must contain letters only, no numbers'),
    body('role').isIn(['Admin','Investigator','Commander','Police Officer','Medical Entry Officer']).withMessage('Invalid role'),
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
            return res.status(400).json({ error: 'Invalid role. Must be Admin, Investigator, Commander, Police Officer, or Medical Entry Officer' });
          return res.status(500).json({ error: 'Failed to create user' });
        }
        logAudit(req.user.id, req.user.service_number, 'USER_CREATE', 'users', this.lastID,
          `Created user ${service_number} (${role})`, req.ip);
        res.json({ success: true, userId: this.lastID });
      });
  }
);

app.put('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  if (req.body.full_name && /[0-9]/.test(req.body.full_name))
    return res.status(400).json({ error: 'Full name must contain letters only, no numbers' });
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

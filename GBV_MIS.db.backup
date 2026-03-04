-- ============================================================
--   RWANDA NATIONAL POLICE
--   Gender-Based Violence Management Information System
--   DATABASE SCHEMA — Full DDL Export
--   Version: 1.0.0  |  Engine: SQLite 3 (upgradeable to PostgreSQL)
-- ============================================================

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;
PRAGMA encoding = "UTF-8";

-- ════════════════════════════════════════════════════════════
-- TABLE 1: USERS
-- Purpose : Stores all authorized system users (officers,
--           investigators, supervisors, admins).
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS users (
    user_id         INTEGER PRIMARY KEY AUTOINCREMENT,
    service_number  TEXT    NOT NULL UNIQUE,
    full_name       TEXT    NOT NULL,
    email           TEXT    UNIQUE,
    phone           TEXT,
    password_hash   TEXT    NOT NULL,         -- SHA-256 hash
    role            TEXT    NOT NULL CHECK(role IN (
                        'admin',
                        'supervisor',
                        'officer',
                        'investigator',
                        'readonly')),
    station         TEXT,
    province        TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1,   -- 0 = suspended
    must_reset_pw   INTEGER NOT NULL DEFAULT 1,   -- force pw change on first login
    last_login      TEXT,
    created_at      TEXT    NOT NULL DEFAULT (datetime('now')),
    created_by      INTEGER REFERENCES users(user_id),
    updated_at      TEXT    NOT NULL DEFAULT (datetime('now'))
);

-- ════════════════════════════════════════════════════════════
-- TABLE 2: PROVINCES (lookup)
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS provinces (
    province_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    province_name TEXT NOT NULL UNIQUE
);

-- ════════════════════════════════════════════════════════════
-- TABLE 3: DISTRICTS (lookup)
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS districts (
    district_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    district_name TEXT NOT NULL,
    province_id   INTEGER NOT NULL REFERENCES provinces(province_id),
    UNIQUE(district_name, province_id)
);

-- ════════════════════════════════════════════════════════════
-- TABLE 4: SURVIVORS
-- Purpose : Confidential survivor profiles. Each survivor is
--           assigned a reference code (SUR-YYYY-NNN) to
--           minimise use of personal identifiers in case tables.
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS survivors (
    survivor_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    survivor_ref      TEXT    NOT NULL UNIQUE,
    full_name         TEXT    NOT NULL,
    national_id       TEXT,
    gender            TEXT    CHECK(gender IN ('Female','Male','Other','Unknown')),
    date_of_birth     TEXT,
    age               INTEGER,
    marital_status    TEXT    CHECK(marital_status IN (
                          'Single','Married','Divorced','Widowed','Cohabiting','Unknown')),
    phone             TEXT,
    address_district  INTEGER REFERENCES districts(district_id),
    address_sector    TEXT,
    address_cell      TEXT,
    address_village   TEXT,
    education_level   TEXT,
    occupation        TEXT,
    disability        TEXT,
    is_minor          INTEGER NOT NULL DEFAULT 0,   -- 1 = under 18
    consent_given     INTEGER NOT NULL DEFAULT 1,
    notes             TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    created_by        INTEGER REFERENCES users(user_id),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ════════════════════════════════════════════════════════════
-- TABLE 5: SUSPECTS
-- Purpose : Records known or unknown suspects per case.
--           full_name may be NULL for unidentified suspects.
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS suspects (
    suspect_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    suspect_ref       TEXT    NOT NULL UNIQUE,
    full_name         TEXT,
    alias             TEXT,
    national_id       TEXT,
    gender            TEXT    CHECK(gender IN ('Male','Female','Unknown')),
    approximate_age   INTEGER,
    phone             TEXT,
    address_district  INTEGER REFERENCES districts(district_id),
    address_sector    TEXT,
    occupation        TEXT,
    nationality       TEXT    DEFAULT 'Rwandan',
    notes             TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    created_by        INTEGER REFERENCES users(user_id),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ════════════════════════════════════════════════════════════
-- TABLE 6: CASES  (central table)
-- Purpose : Core case record linking all other entities.
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS cases (
    case_id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    case_number               TEXT    NOT NULL UNIQUE,     -- GBV-YYYY-NNN
    case_type                 TEXT    NOT NULL CHECK(case_type IN (
                                  'Physical Violence',
                                  'Sexual Violence / Rape',
                                  'Domestic Violence',
                                  'Sexual Harassment',
                                  'Child Abuse (GBV)',
                                  'Forced Marriage',
                                  'Economic Abuse',
                                  'Psychological Abuse',
                                  'Femicide',
                                  'Other GBV')),
    incident_date             TEXT    NOT NULL,
    reporting_date            TEXT    NOT NULL,
    incident_district         INTEGER REFERENCES districts(district_id),
    incident_sector           TEXT,
    incident_cell             TEXT,
    incident_location_detail  TEXT,
    description               TEXT    NOT NULL,
    reporting_source          TEXT    CHECK(reporting_source IN (
                                  'Self-reported (Survivor)',
                                  'Police Patrol',
                                  'Hospital Referral',
                                  'Community Member',
                                  'NGO / CSO',
                                  'Hotline (3511)',
                                  'Other')),
    status                    TEXT    NOT NULL DEFAULT 'Open' CHECK(status IN (
                                  'Open',
                                  'Under Investigation',
                                  'Suspect Arrested',
                                  'Evidence Collected',
                                  'Referred to Prosecution',
                                  'Court Proceedings',
                                  'Closed – Resolved',
                                  'Closed – Withdrawn',
                                  'Closed – Insufficient Evidence')),
    priority                  TEXT    NOT NULL DEFAULT 'Normal' CHECK(priority IN (
                                  'Normal',
                                  'High Priority',
                                  'Urgent / Emergency')),
    survivor_id               INTEGER NOT NULL REFERENCES survivors(survivor_id),
    suspect_id                INTEGER REFERENCES suspects(suspect_id),
    relationship_to_survivor  TEXT    CHECK(relationship_to_survivor IN (
                                  'Spouse / Partner','Ex-partner','Family member',
                                  'Neighbor','Employer','Authority figure',
                                  'Stranger','Unknown')),
    assigned_officer          INTEGER REFERENCES users(user_id),
    assigned_investigator     INTEGER REFERENCES users(user_id),
    supervising_officer       INTEGER REFERENCES users(user_id),
    station                   TEXT,
    closed_at                 TEXT,
    closure_reason            TEXT,
    created_at                TEXT NOT NULL DEFAULT (datetime('now')),
    created_by                INTEGER REFERENCES users(user_id),
    updated_at                TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ════════════════════════════════════════════════════════════
-- TABLE 7: INVESTIGATION_LOGS
-- Purpose : Timestamped log of every investigative action
--           taken on a case. Immutable audit trail.
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS investigation_logs (
    log_id            INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id           INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    log_date          TEXT    NOT NULL DEFAULT (datetime('now')),
    logged_by         INTEGER NOT NULL REFERENCES users(user_id),
    action_taken      TEXT    NOT NULL,
    evidence_ref      TEXT,
    next_action       TEXT,
    next_action_date  TEXT,
    status_after_log  TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ════════════════════════════════════════════════════════════
-- TABLE 8: MEDICAL_REFERRALS
-- Purpose : Tracks referrals to health facilities.
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS medical_referrals (
    referral_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id           INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    survivor_id       INTEGER NOT NULL REFERENCES survivors(survivor_id),
    facility_name     TEXT    NOT NULL,
    facility_type     TEXT    CHECK(facility_type IN (
                          'Hospital','Health Center','Clinic','Mental Health','Other')),
    referral_date     TEXT    NOT NULL,
    referred_by       INTEGER REFERENCES users(user_id),
    referral_reason   TEXT,
    services_needed   TEXT,
    attended          INTEGER DEFAULT 0 CHECK(attended IN (0,1,2)),
                                -- 0=Pending, 1=Attended, 2=Refused
    feedback_notes    TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ════════════════════════════════════════════════════════════
-- TABLE 9: SUPPORT_REFERRALS
-- Purpose : Tracks referrals to legal, shelter, NGO,
--           psychosocial, and child protection services.
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS support_referrals (
    referral_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id           INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    survivor_id       INTEGER NOT NULL REFERENCES survivors(survivor_id),
    referral_type     TEXT    NOT NULL CHECK(referral_type IN (
                          'Legal Aid','Shelter','Psychosocial','NGO / CSO',
                          'Economic Empowerment','Child Protection','Other')),
    organization_name TEXT    NOT NULL,
    contact_person    TEXT,
    contact_phone     TEXT,
    referral_date     TEXT    NOT NULL,
    referred_by       INTEGER REFERENCES users(user_id),
    status            TEXT    DEFAULT 'Pending' CHECK(status IN (
                          'Pending','Active','Completed','Declined')),
    notes             TEXT,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ════════════════════════════════════════════════════════════
-- TABLE 10: EVIDENCE
-- Purpose : Chain-of-custody record for all physical and
--           digital evidence collected per case.
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id           INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id               INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    evidence_ref          TEXT    NOT NULL UNIQUE,    -- EVD-YYYY-NNN
    evidence_type         TEXT    CHECK(evidence_type IN (
                              'Photograph','Medical Report','Witness Statement',
                              'Physical Object','Audio/Video','Document','Other')),
    description           TEXT    NOT NULL,
    collected_date        TEXT,
    collected_by          INTEGER REFERENCES users(user_id),
    storage_location      TEXT,
    chain_of_custody      TEXT,
    is_submitted_court    INTEGER DEFAULT 0,
    created_at            TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ════════════════════════════════════════════════════════════
-- TABLE 11: COURT_PROCEEDINGS
-- Purpose : Tracks court case details, hearings, verdicts
--           and sentences linked to GBV cases.
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS court_proceedings (
    proceeding_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id           INTEGER NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
    court_name        TEXT    NOT NULL,
    court_file_number TEXT,
    charge            TEXT,
    hearing_date      TEXT,
    next_hearing_date TEXT,
    outcome           TEXT,
    verdict           TEXT    CHECK(verdict IN (
                          'Convicted','Acquitted','Dismissed',
                          'Pending','Withdrawn',NULL)),
    sentence          TEXT,
    notes             TEXT,
    created_by        INTEGER REFERENCES users(user_id),
    created_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ════════════════════════════════════════════════════════════
-- TABLE 12: AUDIT_LOG  (append-only)
-- Purpose : Immutable record of every user action for
--           compliance, accountability, and forensic audit.
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS audit_log (
    audit_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp         TEXT    NOT NULL DEFAULT (datetime('now')),
    user_id           INTEGER REFERENCES users(user_id),
    service_number    TEXT,
    action            TEXT    NOT NULL CHECK(action IN (
                          'LOGIN','LOGOUT','LOGIN_FAILED',
                          'CASE_CREATE','CASE_UPDATE','CASE_VIEW','CASE_DELETE',
                          'SURVIVOR_CREATE','SURVIVOR_UPDATE','SURVIVOR_VIEW',
                          'SUSPECT_CREATE','SUSPECT_UPDATE',
                          'USER_CREATE','USER_UPDATE','USER_SUSPEND',
                          'REPORT_VIEW','REPORT_EXPORT',
                          'EVIDENCE_ADD','REFERRAL_CREATE',
                          'PASSWORD_RESET','SETTINGS_CHANGE')),
    target_table      TEXT,
    target_id         INTEGER,
    description       TEXT,
    ip_address        TEXT,
    user_agent        TEXT
);

-- ════════════════════════════════════════════════════════════
-- TABLE 13: NOTIFICATIONS
-- Purpose : In-system alerts sent to officers on case events.
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS notifications (
    notification_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    recipient_id      INTEGER NOT NULL REFERENCES users(user_id),
    case_id           INTEGER REFERENCES cases(case_id),
    message           TEXT    NOT NULL,
    type              TEXT    CHECK(type IN (
                          'Case Assigned','Status Update','Overdue Action',
                          'Urgent Case','System Alert')),
    is_read           INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
);

-- ════════════════════════════════════════════════════════════
-- TABLE 14: SYSTEM_SETTINGS
-- Purpose : Key-value store for configurable system settings.
-- ════════════════════════════════════════════════════════════
CREATE TABLE IF NOT EXISTS system_settings (
    setting_key       TEXT PRIMARY KEY,
    setting_value     TEXT,
    description       TEXT,
    updated_at        TEXT NOT NULL DEFAULT (datetime('now')),
    updated_by        INTEGER REFERENCES users(user_id)
);

-- ════════════════════════════════════════════════════════════
-- INDEXES
-- ════════════════════════════════════════════════════════════
CREATE INDEX IF NOT EXISTS idx_cases_status       ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_type         ON cases(case_type);
CREATE INDEX IF NOT EXISTS idx_cases_district     ON cases(incident_district);
CREATE INDEX IF NOT EXISTS idx_cases_survivor     ON cases(survivor_id);
CREATE INDEX IF NOT EXISTS idx_cases_suspect      ON cases(suspect_id);
CREATE INDEX IF NOT EXISTS idx_cases_officer      ON cases(assigned_officer);
CREATE INDEX IF NOT EXISTS idx_cases_date         ON cases(incident_date);
CREATE INDEX IF NOT EXISTS idx_inv_logs_case      ON investigation_logs(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_case      ON evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_med_ref_case       ON medical_referrals(case_id);
CREATE INDEX IF NOT EXISTS idx_sup_ref_case       ON support_referrals(case_id);
CREATE INDEX IF NOT EXISTS idx_audit_user         ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp    ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_notif_recipient    ON notifications(recipient_id);
CREATE INDEX IF NOT EXISTS idx_survivors_ref      ON survivors(survivor_ref);
CREATE INDEX IF NOT EXISTS idx_suspects_ref       ON suspects(suspect_ref);

-- ════════════════════════════════════════════════════════════
-- VIEWS
-- ════════════════════════════════════════════════════════════

-- V1: Full case summary (anonymised where appropriate)
CREATE VIEW IF NOT EXISTS v_case_summary AS
SELECT
    c.case_number,
    c.case_type,
    c.status,
    c.priority,
    c.incident_date,
    c.reporting_date,
    d.district_name      AS incident_district,
    p.province_name      AS incident_province,
    s.survivor_ref,
    s.gender             AS survivor_gender,
    s.age                AS survivor_age,
    s.is_minor           AS survivor_is_minor,
    sus.suspect_ref,
    sus.full_name        AS suspect_name,
    c.relationship_to_survivor,
    u1.full_name         AS assigned_officer,
    u2.full_name         AS assigned_investigator,
    c.created_at,
    c.updated_at
FROM cases c
LEFT JOIN districts d       ON c.incident_district = d.district_id
LEFT JOIN provinces p       ON d.province_id = p.province_id
LEFT JOIN survivors s       ON c.survivor_id = s.survivor_id
LEFT JOIN suspects sus      ON c.suspect_id = sus.suspect_id
LEFT JOIN users u1          ON c.assigned_officer = u1.user_id
LEFT JOIN users u2          ON c.assigned_investigator = u2.user_id;

-- V2: All referrals per case (medical + support unified)
CREATE VIEW IF NOT EXISTS v_case_referrals AS
SELECT
    c.case_number,
    'Medical'          AS referral_category,
    mr.facility_name   AS organization,
    mr.referral_date,
    CASE mr.attended
        WHEN 1 THEN 'Attended'
        WHEN 2 THEN 'Refused'
        ELSE 'Pending'
    END                AS status,
    u.full_name        AS referred_by
FROM cases c
JOIN medical_referrals mr ON c.case_id = mr.case_id
LEFT JOIN users u ON mr.referred_by = u.user_id
UNION ALL
SELECT
    c.case_number,
    sr.referral_type,
    sr.organization_name,
    sr.referral_date,
    sr.status,
    u.full_name
FROM cases c
JOIN support_referrals sr ON c.case_id = sr.case_id
LEFT JOIN users u ON sr.referred_by = u.user_id;

-- V3: Monthly statistics for dashboard/reports
CREATE VIEW IF NOT EXISTS v_monthly_stats AS
SELECT
    strftime('%Y', incident_date) AS year,
    strftime('%m', incident_date) AS month,
    COUNT(*)                      AS total_cases,
    SUM(CASE WHEN status = 'Closed – Resolved'  THEN 1 ELSE 0 END) AS resolved,
    SUM(CASE WHEN status = 'Open'               THEN 1 ELSE 0 END) AS open_cases,
    SUM(CASE WHEN priority = 'Urgent / Emergency' THEN 1 ELSE 0 END) AS urgent_cases
FROM cases
GROUP BY year, month;

-- ════════════════════════════════════════════════════════════
-- USEFUL QUERIES (for reference / reporting)
-- ════════════════════════════════════════════════════════════

-- All open cases with assigned officer:
-- SELECT case_number, case_type, incident_date, u.full_name AS officer
-- FROM cases c JOIN users u ON c.assigned_officer = u.user_id
-- WHERE c.status = 'Open';

-- Cases involving minors:
-- SELECT c.case_number, c.case_type, s.age, s.gender
-- FROM cases c JOIN survivors s ON c.survivor_id = s.survivor_id
-- WHERE s.is_minor = 1;

-- Cases by province this year:
-- SELECT p.province_name, COUNT(*) AS total
-- FROM cases c
-- JOIN districts d ON c.incident_district = d.district_id
-- JOIN provinces p ON d.province_id = p.province_id
-- WHERE strftime('%Y', c.incident_date) = '2025'
-- GROUP BY p.province_name ORDER BY total DESC;

-- Monthly trend:
-- SELECT year, month, total_cases, resolved FROM v_monthly_stats
-- WHERE year = '2025' ORDER BY month;

-- Full case detail:
-- SELECT * FROM v_case_summary WHERE case_number = 'GBV-2025-001';

-- All referrals for a case:
-- SELECT * FROM v_case_referrals WHERE case_number = 'GBV-2025-001';

-- Evidence chain of custody:
-- SELECT e.evidence_ref, e.evidence_type, e.collected_date,
--        u.full_name AS collected_by, e.storage_location
-- FROM evidence e JOIN users u ON e.collected_by = u.user_id
-- WHERE e.case_id = (SELECT case_id FROM cases WHERE case_number = 'GBV-2025-001');

-- Audit trail for a user:
-- SELECT timestamp, action, description, ip_address FROM audit_log
-- WHERE service_number = 'RNP-2024-001' ORDER BY timestamp DESC;
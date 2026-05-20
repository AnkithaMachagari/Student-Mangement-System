--  SPA_setup.sql
-- ─────────────────────────────────────────────────────────────
--  1. DATABASE
-- ─────────────────────────────────────────────────────────────
CREATE DATABASE IF NOT EXISTS spa_db
    CHARACTER SET  utf8mb4
    COLLATE        utf8mb4_unicode_ci;
 
USE spa_db;
 
-- ─────────────────────────────────────────────────────────────
--  2. GRANT (adjust password / host as needed)
-- ─────────────────────────────────────────────────────────────

CREATE USER IF NOT EXISTS 'spa_app'@'localhost' IDENTIFIED BY 'spa_strong_pwd';
GRANT SELECT, INSERT, UPDATE, DELETE ON spa_db.* TO 'spa_app'@'localhost';
FLUSH PRIVILEGES;
 
-- ─────────────────────────────────────────────────────────────
--  3. TABLES
-- ─────────────────────────────────────────────────────────────
 
-- ── users ────────────────────────────────────────────────────
-- Stores every login account (admin / faculty / student).
-- must_change_pwd = 1 forces the user to set their own password
-- on first login. security_answer is used by the Forgot-Password flow.
CREATE TABLE IF NOT EXISTS users (
    id               INT            NOT NULL AUTO_INCREMENT,
    username         VARCHAR(60)    NOT NULL,
    pwd_hash         VARCHAR(255)   NOT NULL,
    role             ENUM('admin','faculty','student') NOT NULL,
    is_active        TINYINT(1)     NOT NULL DEFAULT 1,
    must_change_pwd  TINYINT(1)     NOT NULL DEFAULT 1,
    security_answer  VARCHAR(255)   DEFAULT NULL,
    subject          VARCHAR(100)   DEFAULT NULL,   
    department       VARCHAR(60)    DEFAULT NULL,   
    created_by       INT            DEFAULT NULL,
    created_at       DATETIME       NOT NULL DEFAULT CURRENT_TIMESTAMP,
    -- ── constraints ──
    PRIMARY KEY (id),
    UNIQUE  KEY uq_username (username),
    CONSTRAINT chk_username_no_spaces CHECK (username NOT LIKE '% %'),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
 
-- ── students ─────────────────────────────────────────────────
-- One record per student account.  Linked 1-to-1 with users.
CREATE TABLE IF NOT EXISTS students (
    id           INT          NOT NULL AUTO_INCREMENT,
    user_id      INT          NOT NULL,
    full_name    VARCHAR(120) NOT NULL,
    department   VARCHAR(60)  NOT NULL,
    enrolled_at  DATE         DEFAULT (CURRENT_DATE),
    PRIMARY KEY (id),
    UNIQUE  KEY uq_user (user_id),
    CONSTRAINT chk_dept CHECK (department IN ('CSE','CST','ECE','IT','MECH')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
 
-- ── subject_marks ────────────────────────────────────────────
-- Stores internal (max 40) + external (max 60) = total marks (max 100)
-- per subject per semester per student.
-- The UNIQUE key prevents duplicate rows for the same
-- student-subject-semester combination.
CREATE TABLE IF NOT EXISTS subject_marks (
    id             INT           NOT NULL AUTO_INCREMENT,
    student_id     INT           NOT NULL,
    subject        VARCHAR(80)   NOT NULL,
    marks          DECIMAL(5,2)  NOT NULL DEFAULT 0,
    internal_marks DECIMAL(5,2)  DEFAULT 0,
    external_marks DECIMAL(5,2)  DEFAULT 0,
    semester       TINYINT       NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uq_student_subject_sem (student_id, subject, semester),
    CONSTRAINT chk_marks_range    CHECK (marks          BETWEEN 0 AND 100),
    CONSTRAINT chk_internal_range CHECK (internal_marks BETWEEN 0 AND 40),
    CONSTRAINT chk_external_range CHECK (external_marks BETWEEN 0 AND 60),
    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE
) ENGINE=InnoDB
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
 
-- ── attendance ───────────────────────────────────────────────
-- One row per student per calendar date.
-- ON DUPLICATE KEY UPDATE allows re-marking the same date.
CREATE TABLE IF NOT EXISTS attendance (
    id          INT       NOT NULL AUTO_INCREMENT,
    student_id  INT       NOT NULL,
    date        DATE      NOT NULL,
    status      ENUM('present','absent') NOT NULL DEFAULT 'present',
    marked_by   INT       DEFAULT NULL,
    marked_at   DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_student_date (student_id, date),
    FOREIGN KEY (student_id) REFERENCES students(id) ON DELETE CASCADE,
    FOREIGN KEY (marked_by)  REFERENCES users(id)    ON DELETE SET NULL
) ENGINE=InnoDB
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
 
-- ── timetable ────────────────────────────────────────────────
-- Weekly schedule slots per department.
CREATE TABLE IF NOT EXISTS timetable (
    id           INT         NOT NULL AUTO_INCREMENT,
    department   VARCHAR(60) NOT NULL,
    day_of_week  ENUM('Monday','Tuesday','Wednesday','Thursday','Friday','Saturday') NOT NULL,
    start_time   TIME        NOT NULL,
    end_time     TIME        NOT NULL,
    subject      VARCHAR(80) NOT NULL,
    faculty      VARCHAR(100) DEFAULT NULL,
    room         VARCHAR(40)  DEFAULT NULL,
    created_by   INT          DEFAULT NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    CONSTRAINT chk_time_order CHECK (end_time > start_time),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
 
-- ── assignments ──────────────────────────────────────────────
-- Assignments posted by faculty, visible to students of that department.
CREATE TABLE IF NOT EXISTS assignments (
    id           INT          NOT NULL AUTO_INCREMENT,
    department   VARCHAR(60)  NOT NULL,
    subject      VARCHAR(80)  NOT NULL,
    title        VARCHAR(200) NOT NULL,
    description  TEXT         DEFAULT NULL,
    due_date     DATE         NOT NULL,
    created_by   INT          DEFAULT NULL,
    created_at   DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
 
-- ── assignment_submissions ───────────────────────────────────
-- One row per student per assignment (student submits text / link).
CREATE TABLE IF NOT EXISTS assignment_submissions (
    id            INT      NOT NULL AUTO_INCREMENT,
    assignment_id INT      NOT NULL,
    student_id    INT      NOT NULL,
    submission    TEXT     NOT NULL,
    status        ENUM('submitted','graded') NOT NULL DEFAULT 'submitted',
    submitted_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    UNIQUE KEY uq_asgn_student (assignment_id, student_id),
    FOREIGN KEY (assignment_id) REFERENCES assignments(id) ON DELETE CASCADE,
    FOREIGN KEY (student_id)    REFERENCES students(id)    ON DELETE CASCADE
) ENGINE=InnoDB
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
 
-- ── pwd_reset_requests ───────────────────────────────────────
-- Faculty / students who cannot self-reset (no security answer)
-- raise a request here; admin resolves it manually.
CREATE TABLE IF NOT EXISTS pwd_reset_requests (
    id           INT         NOT NULL AUTO_INCREMENT,
    user_id      INT         NOT NULL,
    username     VARCHAR(60) NOT NULL,
    role         VARCHAR(20) NOT NULL,
    status       ENUM('pending','resolved') NOT NULL DEFAULT 'pending',
    requested_at DATETIME    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
 
-- ── audit_log ────────────────────────────────────────────────
-- Append-only record of every important action in the system.
CREATE TABLE IF NOT EXISTS audit_log (
    id         INT          NOT NULL AUTO_INCREMENT,
    user_id    INT          DEFAULT NULL,
    actor      VARCHAR(60)  DEFAULT NULL,
    action     VARCHAR(100) NOT NULL,
    details    TEXT         DEFAULT NULL,
    created_at DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;
 
-- ─────────────────────────────────────────────────────────────
--  4. INDEXES  (on frequently-filtered columns)
-- ─────────────────────────────────────────────────────────────
CREATE INDEX IF NOT EXISTS idx_students_dept     ON students       (department);
CREATE INDEX IF NOT EXISTS idx_subj_student      ON subject_marks  (student_id);
CREATE INDEX IF NOT EXISTS idx_subj_subject      ON subject_marks  (subject);
CREATE INDEX IF NOT EXISTS idx_att_student_date  ON attendance     (student_id, date);
CREATE INDEX IF NOT EXISTS idx_audit_actor       ON audit_log      (actor);
CREATE INDEX IF NOT EXISTS idx_timetable_dept    ON timetable      (department);
 
-- ─────────────────────────────────────────────────────────────
--  5. VIEW — student_rank_view
--  Used by: /api/rankings and /api/students/<id>/report-card
--  Computes overall rank, department rank and percentile
--  using MySQL window functions (requires MySQL 8+).
-- ─────────────────────────────────────────────────────────────
CREATE OR REPLACE VIEW student_rank_view AS
SELECT
    s.id,
    s.full_name,
    s.department,
    s.enrolled_at,
    ROUND(COALESCE(AVG(sm.marks), 0), 2)                              AS avg_marks,
    RANK() OVER (ORDER BY COALESCE(AVG(sm.marks), 0) DESC)           AS overall_rank,
    RANK() OVER (
        PARTITION BY s.department
        ORDER BY COALESCE(AVG(sm.marks), 0) DESC
    )                                                                  AS dept_rank,
    ROUND(
        PERCENT_RANK() OVER (ORDER BY COALESCE(AVG(sm.marks), 0))
        * 100, 1
    )                                                                  AS percentile
FROM students s
LEFT JOIN subject_marks sm ON sm.student_id = s.id
GROUP BY s.id, s.full_name, s.department, s.enrolled_at;
 
-- ─────────────────────────────────────────────────────────────
--  6. SAMPLE DATA
-- ─────────────────────────────────────────────────────────────
-- NOTE: Passwords below are bcrypt hashes of the strings shown
--       in the comments.  The seeder script (seed_admin.py)
--       creates the real admin; these rows are demo data only.
 
-- ── Demo users ───────────────────────────────────────────────
-- Passwords are all 'temp1234' (bcrypt hash).
-- Users will be forced to change on first login (must_change_pwd = 1).
INSERT IGNORE INTO users (username, pwd_hash, role, is_active, must_change_pwd, department)
VALUES
-- faculty accounts
('prof_sharma',
 '$2b$12$KIX8zMBm3nRkP1v2t5Y3YuEWdF8nv0jLF6QjPgBOc5sPwhBGdGJby',
 'faculty', 1, 1, 'CSE'),
('prof_reddy',
 '$2b$12$KIX8zMBm3nRkP1v2t5Y3YuEWdF8nv0jLF6QjPgBOc5sPwhBGdGJby',
 'faculty', 1, 1, 'ECE'),
 
-- student accounts (linked below via students table)
('alice2024',
 '$2b$12$KIX8zMBm3nRkP1v2t5Y3YuEWdF8nv0jLF6QjPgBOc5sPwhBGdGJby',
 'student', 1, 1, 'CSE'),
('bob2024',
 '$2b$12$KIX8zMBm3nRkP1v2t5Y3YuEWdF8nv0jLF6QjPgBOc5sPwhBGdGJby',
 'student', 1, 1, 'ECE'),
('carol2024',
 '$2b$12$KIX8zMBm3nRkP1v2t5Y3YuEWdF8nv0jLF6QjPgBOc5sPwhBGdGJby',
 'student', 1, 1, 'IT'),
('david2024',
 '$2b$12$KIX8zMBm3nRkP1v2t5Y3YuEWdF8nv0jLF6QjPgBOc5sPwhBGdGJby',
 'student', 1, 1, 'MECH'),
('eve2024',
 '$2b$12$KIX8zMBm3nRkP1v2t5Y3YuEWdF8nv0jLF6QjPgBOc5sPwhBGdGJby',
 'student', 1, 1, 'CST');
 
-- ── Demo student records ─────────────────────────────────────
INSERT IGNORE INTO students (user_id, full_name, department, enrolled_at)
VALUES
((SELECT id FROM users WHERE username='alice2024'), 'Alice Johnson', 'CSE',  '2023-07-15'),
((SELECT id FROM users WHERE username='bob2024'),   'Bob Martinez',  'ECE',  '2023-07-15'),
((SELECT id FROM users WHERE username='carol2024'), 'Carol Patel',   'IT',   '2023-07-15'),
((SELECT id FROM users WHERE username='david2024'), 'David Kumar',   'MECH', '2023-07-15'),
((SELECT id FROM users WHERE username='eve2024'),   'Eve Thomas',    'CST',  '2023-07-15');
 
-- ── Demo subject marks (semester 1) ─────────────────────────
-- Internal max 40, External max 60, Total stored in `marks`.
INSERT IGNORE INTO subject_marks
    (student_id, subject, internal_marks, external_marks, marks, semester)
SELECT s.id, sub.subject, sub.i, sub.e, sub.i + sub.e, 1
FROM students s
JOIN (
    -- Alice – CSE – high performer
    SELECT 'alice2024' AS uname, 'Math'        AS subject, 38 AS i, 55 AS e UNION ALL
    SELECT 'alice2024', 'Physics',    36, 52 UNION ALL
    SELECT 'alice2024', 'Chemistry',  34, 50 UNION ALL
    SELECT 'alice2024', 'CS',         40, 58 UNION ALL
    SELECT 'alice2024', 'English',    37, 54 UNION ALL
    SELECT 'alice2024', 'DBMS',       39, 57 UNION ALL
    SELECT 'alice2024', 'OS',         38, 56 UNION ALL
    -- Bob – ECE – average
    SELECT 'bob2024',   'Math',       28, 40 UNION ALL
    SELECT 'bob2024',   'Physics',    30, 42 UNION ALL
    SELECT 'bob2024',   'Chemistry',  25, 38 UNION ALL
    SELECT 'bob2024',   'CS',         27, 41 UNION ALL
    SELECT 'bob2024',   'English',    29, 43 UNION ALL
    SELECT 'bob2024',   'DBMS',       26, 39 UNION ALL
    SELECT 'bob2024',   'OS',         28, 40 UNION ALL
    -- Carol – IT – good
    SELECT 'carol2024', 'Math',       33, 48 UNION ALL
    SELECT 'carol2024', 'Physics',    31, 46 UNION ALL
    SELECT 'carol2024', 'Chemistry',  30, 45 UNION ALL
    SELECT 'carol2024', 'CS',         35, 50 UNION ALL
    SELECT 'carol2024', 'English',    32, 47 UNION ALL
    SELECT 'carol2024', 'DBMS',       34, 49 UNION ALL
    SELECT 'carol2024', 'OS',         33, 48 UNION ALL
    -- David – MECH – at risk
    SELECT 'david2024', 'Math',       18, 25 UNION ALL
    SELECT 'david2024', 'Physics',    20, 28 UNION ALL
    SELECT 'david2024', 'Chemistry',  15, 22 UNION ALL
    SELECT 'david2024', 'CS',         19, 26 UNION ALL
    SELECT 'david2024', 'English',    21, 30 UNION ALL
    SELECT 'david2024', 'DBMS',       17, 24 UNION ALL
    SELECT 'david2024', 'OS',         16, 23 UNION ALL
    -- Eve – CST – decent
    SELECT 'eve2024',   'Math',       36, 53 UNION ALL
    SELECT 'eve2024',   'Physics',    34, 51 UNION ALL
    SELECT 'eve2024',   'Chemistry',  32, 49 UNION ALL
    SELECT 'eve2024',   'CS',         37, 54 UNION ALL
    SELECT 'eve2024',   'English',    35, 52 UNION ALL
    SELECT 'eve2024',   'DBMS',       36, 53 UNION ALL
    SELECT 'eve2024',   'OS',         35, 51
) sub ON s.user_id = (SELECT id FROM users WHERE username = sub.uname);
 
-- ── Demo attendance ──────────────────────────────────────────
INSERT IGNORE INTO attendance (student_id, date, status)
SELECT s.id, d.dt, d.st
FROM students s
JOIN (
    SELECT 'alice2024' AS uname, '2024-01-08' AS dt, 'present' AS st UNION ALL
    SELECT 'alice2024', '2024-01-09', 'present' UNION ALL
    SELECT 'alice2024', '2024-01-10', 'absent'  UNION ALL
    SELECT 'alice2024', '2024-01-11', 'present' UNION ALL
    SELECT 'alice2024', '2024-01-12', 'present' UNION ALL
    SELECT 'bob2024',   '2024-01-08', 'absent'  UNION ALL
    SELECT 'bob2024',   '2024-01-09', 'absent'  UNION ALL
    SELECT 'bob2024',   '2024-01-10', 'present' UNION ALL
    SELECT 'bob2024',   '2024-01-11', 'absent'  UNION ALL
    SELECT 'bob2024',   '2024-01-12', 'present' UNION ALL
    SELECT 'carol2024', '2024-01-08', 'present' UNION ALL
    SELECT 'carol2024', '2024-01-09', 'present' UNION ALL
    SELECT 'carol2024', '2024-01-10', 'present' UNION ALL
    SELECT 'carol2024', '2024-01-11', 'present' UNION ALL
    SELECT 'carol2024', '2024-01-12', 'absent'  UNION ALL
    SELECT 'david2024', '2024-01-08', 'absent'  UNION ALL
    SELECT 'david2024', '2024-01-09', 'absent'  UNION ALL
    SELECT 'david2024', '2024-01-10', 'absent'  UNION ALL
    SELECT 'david2024', '2024-01-11', 'present' UNION ALL
    SELECT 'david2024', '2024-01-12', 'absent'  UNION ALL
    SELECT 'eve2024',   '2024-01-08', 'present' UNION ALL
    SELECT 'eve2024',   '2024-01-09', 'present' UNION ALL
    SELECT 'eve2024',   '2024-01-10', 'present' UNION ALL
    SELECT 'eve2024',   '2024-01-11', 'absent'  UNION ALL
    SELECT 'eve2024',   '2024-01-12', 'present'
) d ON s.user_id = (SELECT id FROM users WHERE username = d.uname);
 
-- ── Demo timetable ───────────────────────────────────────────
INSERT IGNORE INTO timetable (department, day_of_week, start_time, end_time, subject, room)
VALUES
('CSE', 'Monday',    '09:00', '10:00', 'DBMS',      'A101'),
('CSE', 'Monday',    '10:00', '11:00', 'OS',         'A102'),
('CSE', 'Tuesday',   '09:00', '10:00', 'Math',       'A103'),
('CSE', 'Wednesday', '11:00', '12:00', 'CS',         'Lab1'),
('ECE', 'Monday',    '09:00', '10:00', 'Physics',    'B201'),
('ECE', 'Tuesday',   '10:00', '11:00', 'Math',       'B202'),
('IT',  'Monday',    '09:00', '10:00', 'CS',         'C301'),
('IT',  'Wednesday', '10:00', '11:00', 'DBMS',       'C302'),
('MECH','Tuesday',   '09:00', '10:00', 'Math',       'D401'),
('MECH','Thursday',  '11:00', '12:00', 'Physics',    'D402'),
('CST', 'Monday',    '09:00', '10:00', 'Chemistry',  'E501'),
('CST', 'Friday',    '10:00', '11:00', 'English',    'E502');
 
-- ── Demo assignment ──────────────────────────────────────────
INSERT IGNORE INTO assignments (department, subject, title, description, due_date)
VALUES
('CSE', 'DBMS',    'ER Diagram Design',      'Design an ER diagram for a hospital management system.', '2024-02-28'),
('ECE', 'Physics', 'Ohm\'s Law Experiment',  'Write a detailed lab report on Ohm\'s Law.', '2024-02-25'),
('IT',  'CS',      'Sorting Algorithms',     'Implement and compare 5 sorting algorithms in Python.', '2024-03-01'),
('CST', 'English', 'Technical Writing',      'Write a 1000-word essay on AI ethics.', '2024-03-05');
 
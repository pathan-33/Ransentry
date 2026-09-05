-- =========================================================
-- RANSOMWARE EARLY WARNING SYSTEM - HONEYPOT DECOY SCHEMA
-- Database: enterprise_sec_vault
-- Dump Date: 2025-02-01
-- =========================================================

CREATE TABLE IF NOT EXISTS system_users (
    user_id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(50) NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    role VARCHAR(30) DEFAULT 'ANALYST',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO system_users (username, password_hash, role) VALUES
('admin_root', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'SUPER_ADMIN'),
('soc_lead', '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8', 'SOC_TIER2'),
('backup_service', '86604a84976c703b417c8a417537dd9be7520e03ec84a923594cf543505c866f', 'SERVICE_ACCT');

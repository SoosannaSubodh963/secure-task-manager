-- ====================================================================
-- Secure Task Management System
-- Database Schema Definition with Enterprise DevSecOps & RBAC
-- 
-- Academic Startup Project: Cloud Computing, DevOps & Cybersecurity
-- Compatible with MySQL 5.7+ / MySQL 8.0+ / MariaDB 10.3+ (XAMPP)
-- ====================================================================

-- 1. Create the Database if it does not already exist
CREATE DATABASE IF NOT EXISTS `secure_task_manager`
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

-- 2. Select the Database
USE `secure_task_manager`;

-- ====================================================================
-- Table: users
-- Purpose: Stores registered user credentials, profile and account status.
-- Security: Passwords stored as Bcrypt/Argon2 hashes; email is unique.
-- ====================================================================
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(150) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `status` ENUM('Active', 'Suspended') NOT NULL DEFAULT 'Active',
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_users_email` (`email`),
    KEY `idx_users_status` (`status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================================
-- Table: tasks
-- Purpose: Stores personal tasks owned by individual users.
-- Features: Workflow approval system (Pending, Approved, Rejected)
-- Security: Strict user isolation enforced at application level via user_id.
-- ====================================================================
CREATE TABLE IF NOT EXISTS `tasks` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT UNSIGNED NOT NULL,
    `title` VARCHAR(255) NOT NULL,
    `description` TEXT NULL,
    `priority` ENUM('Low', 'Medium', 'High') NOT NULL DEFAULT 'Medium',
    `due_date` DATE NULL,
    `status` ENUM('Pending', 'Completed') NOT NULL DEFAULT 'Pending',
    `approval_status` ENUM('Pending', 'Approved', 'Rejected') NOT NULL DEFAULT 'Pending',
    `admin_notes` VARCHAR(255) NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_tasks_user_id` (`user_id`),
    KEY `idx_tasks_status` (`status`),
    KEY `idx_tasks_approval_status` (`approval_status`),
    KEY `idx_tasks_priority` (`priority`),
    KEY `idx_tasks_due_date` (`due_date`),
    CONSTRAINT `fk_tasks_user_id`
        FOREIGN KEY (`user_id`)
        REFERENCES `users` (`id`)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================================
-- Table: audit_logs
-- Purpose: DevSecOps security event audit trail (OWASP A09 Logging & Monitoring).
-- Records logins, task submissions, admin approvals, rejections, and suspensions.
-- ====================================================================
CREATE TABLE IF NOT EXISTS `audit_logs` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT UNSIGNED NULL,
    `action` VARCHAR(100) NOT NULL,
    `details` TEXT NULL,
    `ip_address` VARCHAR(45) NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_audit_user_id` (`user_id`),
    KEY `idx_audit_action` (`action`),
    KEY `idx_audit_created_at` (`created_at`),
    CONSTRAINT `fk_audit_user_id`
        FOREIGN KEY (`user_id`)
        REFERENCES `users` (`id`)
        ON DELETE SET NULL
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================================
-- Seed Initial Accounts (Password is 'Password123!' or 'admin123')
-- ====================================================================
INSERT INTO `users` (`id`, `name`, `email`, `password`, `status`, `created_at`)
VALUES 
(1, 'Demo Student', 'demo@securetask.local', '$2y$10$CEZhZma5Uytex9W4jqYq8u9Uzb9u9q7EOat7R0ZOuY.RnLTmmAs8q', 'Active', NOW()),
(2, 'System Administrator', 'admin@securetask.local', '$2y$10$CEZhZma5Uytex9W4jqYq8u9Uzb9u9q7EOat7R0ZOuY.RnLTmmAs8q', 'Active', NOW())
ON DUPLICATE KEY UPDATE `password` = VALUES(`password`);

-- Seed Demo Tasks (Pre-approved or Pending Review for demonstration)
INSERT INTO `tasks` (`id`, `user_id`, `title`, `description`, `priority`, `due_date`, `status`, `approval_status`, `admin_notes`, `created_at`)
VALUES
(1, 1, 'Configure Local XAMPP Environment', 'Verify Apache and MySQL services are active in XAMPP control panel.', 'High', DATE_ADD(CURRENT_DATE, INTERVAL 1 DAY), 'Completed', 'Approved', 'Verified during system setup.', NOW()),
(2, 1, 'Implement Prepared SQL Statements', 'Protect all task and user queries against SQL injection attacks.', 'High', DATE_ADD(CURRENT_DATE, INTERVAL 2 DAY), 'Completed', 'Approved', 'OWASP Top 10 compliance validated.', NOW()),
(3, 1, 'Set up GitHub Actions CI Pipeline', 'Automate syntax checks, security linting, and automated tests on push.', 'Medium', DATE_ADD(CURRENT_DATE, INTERVAL 3 DAY), 'Pending', 'Pending', NULL, NOW()),
(4, 1, 'Draft Cloud Computing Presentation Slides', 'Prepare architecture diagrams comparing local XAMPP to AWS deployment.', 'Medium', DATE_ADD(CURRENT_DATE, INTERVAL 4 DAY), 'Pending', 'Pending', NULL, NOW()),
(5, 2, 'Perform Enterprise Security Audit', 'Review audit logs and verify multi-tenant isolation guarantees.', 'High', DATE_ADD(CURRENT_DATE, INTERVAL 1 DAY), 'Pending', 'Approved', 'Standard administrative protocol.', NOW())
ON DUPLICATE KEY UPDATE `approval_status` = VALUES(`approval_status`);

-- Seed Initial Security Audit Logs
INSERT INTO `audit_logs` (`user_id`, `action`, `details`, `ip_address`, `created_at`)
VALUES
(2, 'SYSTEM_INIT', 'System initialized with DevSecOps logging and RBAC approval workflow.', '127.0.0.1', NOW()),
(1, 'TASK_CREATED', 'Demo Student submitted task: "Draft Cloud Computing Presentation Slides"', '127.0.0.1', NOW())
ON DUPLICATE KEY UPDATE `action` = `action`;

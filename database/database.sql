-- ====================================================================
-- Secure Task Management System
-- Database Schema Definition
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
-- Purpose: Stores registered user credentials and profile information.
-- Security: Passwords stored as Bcrypt/Argon2 hashes; email is unique.
-- ====================================================================
CREATE TABLE IF NOT EXISTS `users` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(100) NOT NULL,
    `email` VARCHAR(150) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    UNIQUE KEY `uk_users_email` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================================
-- Table: tasks
-- Purpose: Stores personal tasks owned by individual users.
-- Security: Foreign key enforcement prevents orphaned records.
--           Strict user isolation enforced at application level via user_id.
-- ====================================================================
CREATE TABLE IF NOT EXISTS `tasks` (
    `id` INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id` INT UNSIGNED NOT NULL,
    `title` VARCHAR(255) NOT NULL,
    `description` TEXT NULL,
    `priority` ENUM('Low', 'Medium', 'High') NOT NULL DEFAULT 'Medium',
    `due_date` DATE NULL,
    `status` ENUM('Pending', 'Completed') NOT NULL DEFAULT 'Pending',
    `created_at` TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    KEY `idx_tasks_user_id` (`user_id`),
    KEY `idx_tasks_status` (`status`),
    KEY `idx_tasks_priority` (`priority`),
    KEY `idx_tasks_due_date` (`due_date`),
    CONSTRAINT `fk_tasks_user_id`
        FOREIGN KEY (`user_id`)
        REFERENCES `users` (`id`)
        ON DELETE CASCADE
        ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ====================================================================
-- Optional Seed Data for Initial Testing (Password is 'Password123!')
-- Hash generated via password_hash('Password123!', PASSWORD_BCRYPT)
-- ====================================================================
INSERT INTO `users` (`id`, `name`, `email`, `password`, `created_at`)
VALUES 
(1, 'Demo Student', 'demo@securetask.local', '$2y$10$o6V660vN53uU3W2V15kHNu4O/o6bZ3l2QY4f2L21tZ9P8Q4A/e5X2', NOW()),
(2, 'System Administrator', 'admin@securetask.local', '$2y$10$o6V660vN53uU3W2V15kHNu4O/o6bZ3l2QY4f2L21tZ9P8Q4A/e5X2', NOW())
ON DUPLICATE KEY UPDATE `email` = `email`;

INSERT INTO `tasks` (`user_id`, `title`, `description`, `priority`, `due_date`, `status`, `created_at`)
VALUES
(1, 'Configure Local XAMPP Environment', 'Verify Apache and MySQL services are active in XAMPP control panel.', 'High', DATE_ADD(CURRENT_DATE, INTERVAL 1 DAY), 'Completed', NOW()),
(1, 'Implement Prepared SQL Statements', 'Protect all task and user queries against SQL injection attacks.', 'High', DATE_ADD(CURRENT_DATE, INTERVAL 2 DAY), 'Completed', NOW()),
(1, 'Set up GitHub Actions CI Pipeline', 'Automate syntax checks, security linting, and automated tests on push.', 'Medium', DATE_ADD(CURRENT_DATE, INTERVAL 3 DAY), 'Pending', NOW()),
(1, 'Review OWASP Top 10 Compliance', 'Ensure CSRF, XSS, and broken access controls are completely mitigated.', 'Medium', DATE_ADD(CURRENT_DATE, INTERVAL 5 DAY), 'Pending', NOW()),
(1, 'Plan AWS Cloud Migration Strategy', 'Draft architecture diagram for future migration to AWS Elastic Beanstalk and Amazon RDS.', 'Low', DATE_ADD(CURRENT_DATE, INTERVAL 7 DAY), 'Pending', NOW()),
(2, 'Perform System Security Audit', 'Verify database indexes, user sessions, and CSRF token lifecycles.', 'High', DATE_ADD(CURRENT_DATE, INTERVAL 1 DAY), 'Pending', NOW()),
(2, 'Review GitHub Actions CI Build Logs', 'Ensure automated test runners and linters pass without warnings.', 'Medium', DATE_ADD(CURRENT_DATE, INTERVAL 2 DAY), 'Completed', NOW())
ON DUPLICATE KEY UPDATE `title` = `title`;


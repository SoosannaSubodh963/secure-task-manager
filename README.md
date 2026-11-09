# Secure Task Management System

[![CI/CD Pipeline](https://github.com/username/secure-task-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/username/secure-task-manager/actions/workflows/ci.yml)
[![PHP Version](https://img.shields.io/badge/PHP-8.0%20%7C%208.1%20%7C%208.2-777bb4?logo=php)](https://www.php.net/)
[![Database](https://img.shields.io/badge/Database-MySQL%20%7C%20MariaDB-4479a1?logo=mysql)](https://www.mysql.com/)
[![DevSecOps](https://img.shields.io/badge/Security-OWASP%20Top%2010%20Compliant-0d9488)](tests/security-checks.md)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

An academic startup web application designed to demonstrate the real-world convergence of **Cloud Computing**, **DevOps automation**, and **Application Cybersecurity**. Built strictly with Core PHP, MySQL, HTML5, CSS3, and vanilla JavaScript without heavy third-party frameworks.

---

## Table of Contents

1. [Project Introduction](#1-project-introduction)
2. [Problem Statement](#2-problem-statement)
3. [Project Objectives](#3-project-objectives)
4. [Technologies Used](#4-technologies-used)
5. [System Requirements](#5-system-requirements)
6. [Project Folder Structure](#6-project-folder-structure)
7. [XAMPP Installation Requirements](#7-xampp-installation-requirements)
8. [Instructions to Start Apache and MySQL](#8-instructions-to-start-apache-and-mysql)
9. [Instructions to Copy the Project into htdocs](#9-instructions-to-copy-the-project-into-htdocs)
10. [Instructions to Import database.sql through phpMyAdmin](#10-instructions-to-import-databasesql-through-phpmyadmin)
11. [Database Configuration Instructions](#11-database-configuration-instructions)
12. [Instructions to Run the Application](#12-instructions-to-run-the-application)
13. [User Registration and Login Instructions](#13-user-registration-and-login-instructions)
14. [Explanation of CRUD Operations](#14-explanation-of-crud-operations)
15. [Cybersecurity Features Implemented](#15-cybersecurity-features-implemented)
16. [GitHub Integration Instructions](#16-github-integration-instructions)
17. [CI/CD Pipeline Explanation](#17-cicd-pipeline-explanation)
18. [Future Cloud Deployment Possibilities](#18-future-cloud-deployment-possibilities)

---

## 1. Project Introduction

The **Secure Task Management System** is a full-featured, multi-tenant productivity platform engineered to illustrate how modern security best practices and DevOps automation can be implemented directly into a lightweight web stack.

The platform provides users with an isolated personal task environment where they can track deadlines, assign priorities, and update project milestones. The architecture has been intentionally developed from scratch to demonstrate fundamental web engineering concepts: secure session persistence, defense against the OWASP Top 10 web vulnerabilities, database integrity, and automated continuous integration.

---

## 2. Problem Statement

Many modern web developers rely heavily on high-level frameworks (e.g., Laravel, React, Django) that abstract away core security and operational mechanisms. As a result:
- Students and early-career engineers frequently lack hands-on understanding of how **SQL Injection**, **Cross-Site Scripting (XSS)**, **CSRF**, and **Broken Object-Level Authorization (IDOR)** actually occur and how they are mitigated at the protocol and database driver level.
- Applications often suffer from improper session handling, unhashed or weakly hashed credentials, and leaky error messages.
- Development processes often overlook early automated testing and continuous integration (CI/CD) pipelines before deploying code.

This project directly addresses these challenges by delivering an accessible, transparent, and battle-tested reference implementation using Core PHP and MySQL with comprehensive security mechanisms and automated GitHub Actions verification.

---

## 3. Project Objectives

- **Educational Clarity:** Deliver clean, well-commented, readable code without framework abstraction.
- **Robust Cybersecurity:** Implement defense-in-depth protections covering SQL injection, XSS, CSRF, session fixation, and unauthorized cross-tenant data access.
- **Complete Task Lifecycle:** Provide intuitive, responsive CRUD operations with dynamic status toggles, priority levels, and due date alerts.
- **DevOps Integration:** Establish an automated CI pipeline with GitHub Actions executing PHP linting, static security audits, and functional tests.
- **Cloud Readiness:** Decouple environment configuration from the codebase to simplify future containerization and cloud hosting on AWS, Microsoft Azure, or GCP.

---

## 4. Technologies Used

### Frontend
- **HTML5:** Semantic document structure with accessible forms and modals.
- **CSS3:** Custom responsive layout, CSS variables, navy blue & soft teal palette, card animations. No Bootstrap, Tailwind, or external styling dependencies.
- **Vanilla JavaScript:** Modal management, auto-dismissing alerts, real-time client-side password match validation.

### Backend
- **Core PHP (8.0+ / 8.2 Recommended):** Server-side routing, request handling, and business logic.
- **PHP Data Objects (PDO):** Native database interface with prepared statements and emulated prepares disabled.

### Database
- **MySQL / MariaDB:** Relational schema with primary keys, indexes, foreign key cascading, and UTF-8 multibyte (`utf8mb4`) support.
- **phpMyAdmin:** Web-based GUI bundled with XAMPP for database administration.

### DevOps & CI/CD
- **Git & GitHub:** Distributed version control and branch management.
- **GitHub Actions:** Automated continuous integration pipeline (`.github/workflows/ci.yml`).

---

## 5. System Requirements

- **Operating System:** Windows 10/11 (or macOS / Linux).
- **Web Server:** Apache (via XAMPP).
- **PHP Runtime:** PHP 8.0, 8.1, or 8.2 with PDO, pdo_mysql, and session extensions enabled.
- **Database Server:** MySQL 5.7+ / MySQL 8.0+ or MariaDB 10.3+.
- **Web Browser:** Any modern web browser (Google Chrome, Mozilla Firefox, Microsoft Edge, Safari).
- **Git:** Git 2.30+ installed for version control.

---

## 6. Project Folder Structure

```text
secure-task-manager/
│
├── index.php                      # Public landing page (Hero, features, academic showcase)
├── register.php                   # User registration module with validation & password hashing
├── login.php                      # User login module with session fixation prevention
├── logout.php                     # Secure session termination and cookie destruction
├── dashboard.php                  # Authenticated user dashboard with stats & task list
├── add_task.php                   # Task creation controller and form
├── edit_task.php                  # Task editing controller and authorization check
├── delete_task.php                # Task deletion handler (POST only + CSRF protected)
├── update_status.php              # Instant task completion toggle (Pending / Completed)
│
├── config/
│   ├── db.php                     # Secure PDO database connection handler
│   └── config.local.example.php   # Optional local database credentials override template
│
├── includes/
│   ├── auth.php                   # Authentication guards, session config & escaping helper e()
│   ├── csrf.php                   # Cryptographic CSRF token generation & verification
│   ├── header.php                 # Global navigation bar, alert banners, and HTML head
│   └── footer.php                 # Global footer, copyright, and script links
│
├── assets/
│   ├── css/
│   │   └── style.css              # Custom stylesheet (white bg, navy blue & soft teal accents)
│   └── js/
│       └── script.js              # Client-side validation, modal triggers & alert handling
│
├── database/
│   └── database.sql               # Complete database schema, indexes, and initial demo seed
│
├── tests/
│   ├── run-tests.php              # Automated test runner for CLI & GitHub Actions
│   └── security-checks.md         # Comprehensive cybersecurity audit report & threat model
│
├── .github/
│   └── workflows/
│       └── ci.yml                 # Automated GitHub Actions CI workflow configuration
│
├── .gitignore                     # Git ignore rules for credentials, OS, and temp files
└── README.md                      # Comprehensive project documentation
```

---

## 7. XAMPP Installation Requirements

If XAMPP is not yet installed on your Windows machine:
1. Download the official installer for Windows from [Apache Friends](https://www.apachefriends.org/).
2. Run the installer and select **Apache**, **MySQL**, **PHP**, and **phpMyAdmin**.
3. Install to the default path: `C:\xampp`.
4. Finish installation and launch the **XAMPP Control Panel**.

---

## 8. Instructions to Start Apache and MySQL

1. Launch **XAMPP Control Panel** from the Windows Start Menu or by running `C:\xampp\xampp-control.exe`.
2. Locate **Apache** in the Modules list and click the **Start** button. The background turns green when active (Default Port: 80, 443).
3. Locate **MySQL** in the Modules list and click the **Start** button. The background turns green when active (Default Port: 3306).

> **Tip:** If port 80 is occupied by another service (like Skype or IIS), open the XAMPP Control Panel, click **Config** next to Apache, edit `httpd.conf`, and adjust `Listen 80` to `Listen 8080`.

---

## 9. Instructions to Copy the Project into htdocs

Apache serves web files from the `htdocs` directory inside XAMPP.

1. Navigate to your project directory.
2. Copy the entire project folder into your XAMPP web root:
   ```text
   Source:      c:\Users\<YourUser>\OneDrive\Desktop\NormalProject\
   Destination: C:\xampp\htdocs\secure-task-manager\
   ```
3. Ensure the target folder looks like this:
   ```text
   C:\xampp\htdocs\secure-task-manager\index.php
   C:\xampp\htdocs\secure-task-manager\config\db.php
   C:\xampp\htdocs\secure-task-manager\database\database.sql
   ...
   ```

*Windows PowerShell one-line copy command:*
```powershell
Copy-Item -Path "c:\Users\soosa\OneDrive\Desktop\NormalProject" -Destination "C:\xampp\htdocs\secure-task-manager" -Recurse -Force
```

---

## 10. Instructions to Import database.sql through phpMyAdmin

1. Open your web browser and navigate to:
   ```
   http://localhost/phpmyadmin/
   ```
2. Click on the **Databases** tab in the top navigation bar.
3. In the "Create database" field, enter `secure_task_manager` and select collation `utf8mb4_unicode_ci`, then click **Create**.
4. In the left sidebar, click on the newly created **secure_task_manager** database.
5. Click on the **Import** tab at the top.
6. Click **Choose File** (or "Browse") and select:
   ```text
   C:\xampp\htdocs\secure-task-manager\database\database.sql
   ```
7. Scroll down to the bottom of the page and click **Import** (or "Go").
8. phpMyAdmin will display a green success notification:
   ```text
   Import has been successfully finished, queries executed.
   ```
   You will see two tables: `users` and `tasks`.

---

## 11. Database Configuration Instructions

The database connection is established in `config/db.php`.

By default, XAMPP configures MySQL with:
- **Host:** `localhost`
- **Port:** `3306`
- **Database:** `secure_task_manager`
- **Username:** `root`
- **Password:** `""` (empty string / no password)

`config/db.php` automatically connects using these default credentials out of the box. No manual file changes are required for standard XAMPP setups!

### Custom Configuration (Production or Custom MySQL)
If your MySQL root user has a password, copy `config/config.local.example.php` to `config/config.local.php`:
```php
<?php
return [
    'host' => 'localhost',
    'port' => '3306',
    'name' => 'secure_task_manager',
    'user' => 'root',
    'pass' => 'YourSecretPassword',
];
```
> **Security Note:** `config.local.php` is explicitly ignored in `.gitignore` to prevent committing live credentials to GitHub.

---

## 12. Instructions to Run the Application

1. Ensure Apache and MySQL are running in the XAMPP Control Panel.
2. Open your web browser and visit:
   ```
   http://localhost/secure-task-manager/
   ```
3. You will be greeted by the **Secure Task Management System** landing page displaying the feature overview, architecture highlights, and navigation links.

---

## 13. User Registration and Login Instructions

### Pre-seeded Demo Account
For rapid testing, a demo account is pre-seeded in the database:
- **Email:** `demo@securetask.local`
- **Password:** `Password123!`

### Registering a New Account
1. Click **Get Started** or navigate to `http://localhost/secure-task-manager/register.php`.
2. Fill in the fields:
   - **Full Name:** Minimum 2 characters (e.g., *Jane Developer*).
   - **Email Address:** A valid email (e.g., *jane@example.com*).
   - **Password:** Minimum 8 characters including letters and numbers (e.g., *TaskPass2026!*).
   - **Confirm Password:** Must match your password.
3. Click **Create My Account**.
4. You will receive a success banner redirecting you to `login.php`.

### Logging In
1. Navigate to `http://localhost/secure-task-manager/login.php`.
2. Enter your registered email address and password.
3. Click **Sign In**.
4. Upon successful validation, your session identifier is regenerated and you are escorted to your **Dashboard**.

---

## 14. Explanation of CRUD Operations

The task management module supports the complete lifecycle of tasks:

| Operation | Action | Route | Security Mechanism |
| :--- | :--- | :--- | :--- |
| **Create (C)** | Add a new task with title, description, priority, and due date. | `add_task.php` or Quick Add Modal on `dashboard.php` | Input validation, CSRF verification, prepared `INSERT` assigning authenticated `user_id`. |
| **Read (R)** | Display tasks owned strictly by the logged-in user with filter tabs (All, Pending, Completed, High Priority) and keyword search. | `dashboard.php` | Scoped via `WHERE user_id = :user_id`. Output escaped via `e()` to block XSS. |
| **Update (U)** | Modify task titles, details, deadlines, priority, or toggle between Pending and Completed. | `edit_task.php` & `update_status.php` | Scoped via `WHERE id = :id AND user_id = :user_id`. Rejects modifications to other users' tasks. |
| **Delete (D)** | Remove an unwanted task after interactive user confirmation. | `delete_task.php` | Strictly accepts `POST` requests with a valid CSRF token. Authorization checks user ownership before deleting. |

---

## 15. Cybersecurity Features Implemented

Security is embedded into every tier of the application:

1. **SQL Injection Defense (Prepared Statements):**
   - Implemented via PHP Data Objects (PDO).
   - `PDO::ATTR_EMULATE_PREPARES => false` forces real server-side prepared statements in MySQL. User data is never concatenated directly into SQL strings.
2. **Cross-Site Scripting (XSS) Prevention:**
   - All dynamic output rendered into HTML passes through the centralized `e()` helper:
     ```php
     htmlspecialchars($string ?? '', ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
     ```
   - Malicious payloads such as `<script>alert(1)</script>` render as harmless text literals.
3. **Cross-Site Request Forgery (CSRF) Protection:**
   - Implements the Synchronizer Token Pattern with high-entropy 256-bit cryptographically secure pseudorandom tokens (`bin2hex(random_bytes(32))`).
   - Every state-changing form embeds `<?= csrf_field(); ?>`.
   - Verified on form submissions using timing-attack safe `hash_equals()`.
4. **Cryptographic Password Hashing:**
   - Passwords are never stored in plaintext.
   - Hashed using PHP's native `password_hash($password, PASSWORD_DEFAULT)` utilizing adaptive Bcrypt algorithms with automatically randomized salts.
   - Verified via `password_verify()`.
5. **Secure Session Management:**
   - Prevents Session Fixation by calling `session_regenerate_id(true)` immediately upon login.
   - Cookies configured with `HttpOnly` (blocks JavaScript access to mitigate cookie theft) and `SameSite=Lax` (guards against cross-site leakage).
   - Automated inactivity timeout invalidates stale sessions after 30 minutes.
6. **Multi-Tenant Authorization & IDOR Immunity:**
   - Every SQL query checks `user_id = :user_id`.
   - Modifying URL parameters (e.g., `edit_task.php?id=999`) will not leak or alter another user's task.
7. **Safe Error Handling & Information Disclosure:**
   - Raw database connection exceptions are caught, logged server-side via `error_log()`, and replaced with user-friendly notices without leaking credentials, database names, or query traces.

---

## 16. GitHub Integration Instructions

To version-control this project and push it to your GitHub profile:

1. Open PowerShell or Command Prompt in the project folder:
   ```powershell
   cd c:\Users\soosa\OneDrive\Desktop\NormalProject
   ```
2. Initialize Git and verify branch name:
   ```bash
   git init
   git branch -M main
   ```
3. Stage and commit the codebase:
   ```bash
   git add .
   git commit -m "feat: Initial commit of Secure Task Management System with CI/CD and DevSecOps"
   ```
4. Create a new public or private repository on GitHub named `secure-task-manager`.
5. Link your local repository to GitHub:
   ```bash
   git remote add origin https://github.com/<your-username>/secure-task-manager.git
   ```
6. Push code to the repository:
   ```bash
   git push -u origin main
   ```

---

## 17. CI/CD Pipeline Explanation

Continuous Integration is automated using **GitHub Actions** defined in `.github/workflows/ci.yml`.

### Workflow Stages:
1. **Trigger:** Automatically runs on every `push` to `main` or upon creating a `pull_request`.
2. **Environment Matrix:** Boots an Ubuntu Linux runner and installs PHP 8.2 with PDO, MySQL, mbstring, and JSON extensions.
3. **Syntax Validation (Linting):**
   - Executes `php -l` on every PHP file in the repository.
   - Any syntax mistake or unclosed delimiter fails the build immediately.
4. **Automated Test Suite Execution:**
   - Runs `php tests/run-tests.php`.
   - Validates XSS escaping, password verification, CSRF token generation, session cookie parameters, SQL schema integrity, and checks for unsafe SQL queries.
5. **Secrets & Git Hygiene Audit:**
   - Scans Git history and tracked files to ensure no live credential files (`config.local.php`, `.env`) are committed to GitHub.
6. **Status Badge:** Reports pass/fail status back to GitHub pull requests and repository badges.

---

## 18. Future Cloud Deployment Possibilities

While the application is configured to run smoothly in local XAMPP environments, its decoupled architecture makes it ready for future cloud migration:

1. **Containerization (Docker & Docker Compose):**
   - Package Apache, PHP 8.2, and MySQL into lightweight Docker containers for reproducible staging and production environments.
2. **AWS Cloud Architecture:**
   - **Compute:** Deploy the PHP application layer on **AWS Elastic Beanstalk** or **Amazon ECS (Elastic Container Service)**.
   - **Database:** Host the database on **Amazon RDS for MySQL** with automated Multi-AZ failover and encrypted storage (AWS KMS).
   - **Security:** Place the compute instances in private VPC subnets behind an **Application Load Balancer (ALB)** with **AWS WAF (Web Application Firewall)** to block common web exploits.
   - **Secrets Management:** Store production database credentials securely in **AWS Secrets Manager** or **AWS Systems Manager Parameter Store**.
3. **Automated Continuous Deployment (CD):**
   - Extend the existing `.github/workflows/ci.yml` pipeline with automated deployment steps that push Docker images to Amazon ECR and deploy them to cloud infrastructure upon successful CI testing.

---

## Academic Demonstration & Verification Checklist

- [x] Application functions completely in local XAMPP (`http://localhost/secure-task-manager/`).
- [x] Full CRUD operations verified (Create, Read, Update, Delete, Toggle Status).
- [x] Multi-tenant isolation verified (Users only see and modify their own tasks).
- [x] SQL Injection protection verified with PDO prepared statements.
- [x] XSS protection verified with contextual HTML entity escaping.
- [x] CSRF protection verified on all state-changing actions.
- [x] Cryptographic password hashing verified with Bcrypt (`password_hash`).
- [x] Session fixation protection verified (`session_regenerate_id`).
- [x] Clean, modern, responsive UI in navy blue and soft teal accents.
- [x] Automated test runner (`tests/run-tests.php`) passes 7/7 checks.
- [x] GitHub Actions CI pipeline (`.github/workflows/ci.yml`) configured for automated checks.
- [x] DevSecOps security report documented in `tests/security-checks.md`.

<?php
/**
 * ====================================================================
 * Secure Task Management System
 * Database Connection Module
 * 
 * DevSecOps & Cybersecurity Implementation:
 * - Uses PHP Data Objects (PDO) for secure, prepared SQL execution.
 * - Enforces PDO::ATTR_EMULATE_PREPARES => false to ensure real prepared
 *   statements are executed by the MySQL engine (SQLi immunity).
 * - Implements secure credential isolation (Environment variables or config.local.php).
 * - Suppresses raw database errors from end-users to prevent information disclosure.
 * ====================================================================
 */

// Prevent direct script execution if accessed outside application scope
if (basename($_SERVER['SCRIPT_FILENAME'] ?? '') === 'db.php') {
    http_response_code(403);
    exit('Access Denied');
}

// 1. Default local XAMPP configuration
$db_host = 'localhost';
$db_port = '3306';
$db_name = 'secure_task_manager';
$db_user = 'root';
$db_pass = '';
$db_charset = 'utf8mb4';

// 2. Allow environment variables to override defaults (Ideal for CI/CD pipelines & Docker/Cloud)
if (getenv('DB_HOST'))    $db_host = getenv('DB_HOST');
if (getenv('DB_PORT'))    $db_port = getenv('DB_PORT');
if (getenv('DB_NAME'))    $db_name = getenv('DB_NAME');
if (getenv('DB_USER'))    $db_user = getenv('DB_USER');
if (getenv('DB_PASS') !== false) $db_pass = getenv('DB_PASS');

// 3. Optional local configuration file (ignored by Git for production secrets)
$local_config_file = __DIR__ . '/config.local.php';
if (file_exists($local_config_file)) {
    $local_cfg = include $local_config_file;
    if (is_array($local_cfg)) {
        $db_host = $local_cfg['host'] ?? $db_host;
        $db_port = $local_cfg['port'] ?? $db_port;
        $db_name = $local_cfg['name'] ?? $db_name;
        $db_user = $local_cfg['user'] ?? $db_user;
        $db_pass = $local_cfg['pass'] ?? $db_pass;
    }
}

// 4. Construct Data Source Name (DSN)
$dsn = "mysql:host={$db_host};port={$db_port};dbname={$db_name};charset={$db_charset}";

// 5. PDO Connection Options
$options = [
    // Throw exceptions on error so they can be caught and handled securely
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    // Return rows as associative arrays by default
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    // Disable emulated prepares to enforce server-side prepared statements
    PDO::ATTR_EMULATE_PREPARES   => false,
    // Persistent connections disabled for predictable state management
    PDO::ATTR_PERSISTENT         => false,
];

try {
    $pdo = new PDO($dsn, $db_user, $db_pass, $options);
} catch (PDOException $e) {
    // SECURITY: Log error details server-side only; never expose credentials or stack traces to clients
    error_log("[Database Connection Error] " . $e->getMessage());

    // Display user-friendly error message
    http_response_code(500);
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Database Error - Secure Task Manager</title>
        <style>
            body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #f8fafc; display: flex; align-items: center; justify-content: center; height: 100vh; margin: 0; padding: 1rem; }
            .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 2rem; max-width: 550px; text-align: center; box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5); }
            h1 { color: #f87171; font-size: 1.5rem; margin-top: 0; }
            p { color: #cbd5e1; line-height: 1.6; font-size: 0.95rem; }
            .box { background: #0f172a; border-radius: 8px; padding: 1rem; text-align: left; font-family: monospace; font-size: 0.85rem; color: #38bdf8; margin: 1rem 0; overflow-x: auto; }
            .btn { display: inline-block; background: #0d9488; color: #fff; padding: 0.6rem 1.2rem; border-radius: 6px; text-decoration: none; font-weight: 600; margin-top: 0.5rem; transition: background 0.2s; }
            .btn:hover { background: #0f766e; }
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Database Connection Notice</h1>
            <p>The application could not connect to MySQL. If you are running locally in XAMPP, please verify that:</p>
            <div class="box">
                1. The MySQL service is running in XAMPP Control Panel.<br>
                2. The database <strong>secure_task_manager</strong> has been imported via phpMyAdmin.<br>
                3. File <strong>database/database.sql</strong> was executed successfully.
            </div>
            <p>For more setup details, refer to the <code>README.md</code> included in this project.</p>
            <a href="index.php" class="btn">Retry Connection</a>
        </div>
    </body>
    </html>
    <?php
    exit;
}

/**
 * Helper function to retrieve database connection instance.
 * 
 * @return PDO
 */
function get_db(): PDO {
    global $pdo;
    return $pdo;
}

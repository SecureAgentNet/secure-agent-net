<?php
// =============================================================================
// SAN Blog – Configuration
// =============================================================================

define('DB_HOST',     'localhost');
define('DB_NAME',     'san_blog');
define('DB_USER',     'bdgkwy_0');
define('DB_PASS',     'd2}F=(1*#oEY');
define('DB_CHARSET',  'utf8mb4');

define('SITE_URL',    'https://secureagentnet.com');
define('UPLOAD_DIR',  __DIR__ . '/uploads');
define('UPLOAD_URL',  SITE_URL . '/blog/backend/uploads');

define('ADMIN_USERNAME', 'admin');
define('ADMIN_PASSWORD_HASH', '$2y$12$bWundKlCJKwUUdWOnzbuqeN0kkb4FkHJ6MJT0fYgX3BFDbf/V/3.S');

// Timezone
date_default_timezone_set('UTC');

// Error reporting (disable display in production, just log)
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');
ini_set('error_log', __DIR__ . '/error.log');

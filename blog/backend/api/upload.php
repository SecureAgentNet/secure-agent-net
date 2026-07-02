<?php
// =============================================================================
// SAN Blog – API: Upload
// Endpoint:
//   POST /api/upload  – upload cover image (auth required)
// =============================================================================

require_once __DIR__ . '/../helpers.php';

handleCors();

session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    jsonResponse(['error' => 'Method not allowed'], 405);
}

// Auth check
if (empty($_SESSION['san_admin_logged_in'])) {
    jsonResponse(['error' => 'Unauthorized'], 401);
}

if (!isset($_FILES['file'])) {
    jsonResponse(['error' => 'No file uploaded'], 400);
}

$file = $_FILES['file'];

// Validate
$allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'image/svg+xml'];
if (!in_array($file['type'], $allowedTypes)) {
    jsonResponse(['error' => 'Invalid file type. Allowed: JPEG, PNG, GIF, WebP, SVG'], 400);
}

$maxSize = 5 * 1024 * 1024; // 5 MB
if ($file['size'] > $maxSize) {
    jsonResponse(['error' => 'File too large. Max 5 MB'], 400);
}

// Generate unique filename
$ext      = pathinfo($file['name'], PATHINFO_EXTENSION);
$filename = uniqid('blog_', true) . '.' . strtolower($ext);
$destPath = UPLOAD_DIR . '/' . $filename;

if (!move_uploaded_file($file['tmp_name'], $destPath)) {
    jsonResponse(['error' => 'Failed to save file'], 500);
}

jsonResponse([
    'message' => 'Upload successful',
    'url'     => UPLOAD_URL . '/' . $filename,
    'filename' => $filename,
], 201);

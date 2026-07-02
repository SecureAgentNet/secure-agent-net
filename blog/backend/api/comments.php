<?php
// =============================================================================
// SAN Blog – API: Comments
// Endpoints:
//   GET  /api/comments?post_id={id}  – approved comments for a post
//   POST /api/comments               – submit a new comment
// =============================================================================

require_once __DIR__ . '/../helpers.php';

handleCors();

$method = $_SERVER['REQUEST_METHOD'];
$db     = getDB();

// --- GET /api/comments?post_id={id} ---
if ($method === 'GET') {
    $postId = (int) ($_GET['post_id'] ?? 0);

    if ($postId <= 0) {
        jsonResponse(['error' => 'Missing post_id parameter'], 400);
    }

    $stmt = $db->prepare('
        SELECT id, parent_id, author_name, body, created_at
        FROM comments
        WHERE post_id = :pid AND is_approved = 1
        ORDER BY created_at ASC
    ');
    $stmt->execute(['pid' => $postId]);
    $comments = $stmt->fetchAll();

    jsonResponse($comments);
}

// --- POST /api/comments ---
if ($method === 'POST') {
    $input = jsonInput();
    requireFields($input, ['post_id', 'author_name', 'author_email', 'body']);

    $postId      = (int) $input['post_id'];
    $parentId    = !empty($input['parent_id']) ? (int) $input['parent_id'] : null;
    $authorName  = trim($input['author_name']);
    $authorEmail = trim($input['author_email']);
    $body        = trim($input['body']);

    // Validate email format
    if (!filter_var($authorEmail, FILTER_VALIDATE_EMAIL)) {
        jsonResponse(['error' => 'Invalid email address'], 400);
    }

    // Verify post exists
    $pStmt = $db->prepare('SELECT id FROM posts WHERE id = :id AND status = \'published\'');
    $pStmt->execute(['id' => $postId]);
    if (!$pStmt->fetch()) {
        jsonResponse(['error' => 'Post not found'], 404);
    }

    // Verify parent comment if set
    if ($parentId) {
        $cStmt = $db->prepare('SELECT id FROM comments WHERE id = :id AND post_id = :pid');
        $cStmt->execute(['id' => $parentId, 'pid' => $postId]);
        if (!$cStmt->fetch()) {
            jsonResponse(['error' => 'Parent comment not found'], 404);
        }
    }

    $stmt = $db->prepare('
        INSERT INTO comments (post_id, parent_id, author_name, author_email, body, is_approved)
        VALUES (:pid, :parent_id, :author_name, :author_email, :body, 1)
    ');
    $stmt->execute([
        'pid'          => $postId,
        'parent_id'    => $parentId,
        'author_name'  => $authorName,
        'author_email' => $authorEmail,
        'body'         => $body,
    ]);

    jsonResponse([
        'message'    => 'Comment submitted successfully',
        'comment_id' => (int) $db->lastInsertId(),
    ], 201);
}

jsonResponse(['error' => 'Method not allowed'], 405);

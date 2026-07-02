<?php
// =============================================================================
// SAN Blog – API: Posts
// Endpoints:
//   GET  /api/posts           – list published posts (supports ?page=&limit=&category=&tag=)
//   GET  /api/posts/{slug}    – single post by slug
//   POST /api/posts           – create post (auth required)
//   PUT  /api/posts/{id}      – update post (auth required)
//   DELETE /api/posts/{id}    – delete post (auth required)
// =============================================================================

require_once __DIR__ . '/../helpers.php';

handleCors();

$method  = $_SERVER['REQUEST_METHOD'];
$db      = getDB();

// --- AUTH HELPER (simple session check) ---
session_start();
function isAuthenticated(): bool
{
    return !empty($_SESSION['san_admin_logged_in']);
}

function requireAuth(): void
{
    if (!isAuthenticated()) {
        jsonResponse(['error' => 'Unauthorized'], 401);
    }
}

// --- ROUTING ---
// Parse the path: /api/posts[/{identifier}]
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Strip prefix to get the action.  Assumes preceding path like /blog/backend/api/posts/...
// We try to extract the part after 'api/posts'
$basePattern = '#/api/posts(?:/([^/]+))?#';
$identifier = null;

if (preg_match($basePattern, $requestUri, $m)) {
    $identifier = $m[1] ?? null;
}

// --- GET /api/posts ---
if ($method === 'GET' && !$identifier) {
    $page     = max(1, (int) ($_GET['page'] ?? 1));
    $limit    = min(50, max(1, (int) ($_GET['limit'] ?? 12)));
    $offset   = ($page - 1) * $limit;
    $category = $_GET['category'] ?? null;
    $tag      = $_GET['tag'] ?? null;

    $where  = "WHERE p.status = 'published'";
    $params = [];

    if ($category) {
        $where .= ' AND EXISTS (
            SELECT 1 FROM post_categories pc
            INNER JOIN categories c ON pc.category_id = c.id
            WHERE pc.post_id = p.id AND c.slug = :cat_slug
        )';
        $params['cat_slug'] = $category;
    }

    if ($tag) {
        $where .= ' AND EXISTS (
            SELECT 1 FROM post_tags pt
            INNER JOIN tags t ON pt.tag_id = t.id
            WHERE pt.post_id = p.id AND t.slug = :tag_slug
        )';
        $params['tag_slug'] = $tag;
    }

    // Count total
    $countSql = "SELECT COUNT(*) FROM posts p $where";
    $stmt = $db->prepare($countSql);
    $stmt->execute($params);
    $total = (int) $stmt->fetchColumn();

    // Fetch posts
    $sql = "SELECT id, title, slug, summary, cover_image, author, read_time, published_at, created_at
            FROM posts p
            $where
            ORDER BY published_at DESC
            LIMIT $limit OFFSET $offset";
    $stmt = $db->prepare($sql);
    $stmt->execute($params);
    $posts = $stmt->fetchAll();

    // Attach tags & categories
    foreach ($posts as &$post) {
        $post['tags']       = getPostTags($db, (int) $post['id']);
        $post['categories'] = getPostCategories($db, (int) $post['id']);
    }

    jsonResponse([
        'data'       => $posts,
        'pagination' => [
            'page'       => $page,
            'limit'      => $limit,
            'total'      => $total,
            'totalPages' => (int) ceil($total / $limit),
        ],
    ]);
}

// --- GET /api/posts/{slug} ---
if ($method === 'GET' && $identifier) {
    $stmt = $db->prepare('SELECT * FROM posts WHERE slug = :slug AND status = \'published\'');
    $stmt->execute(['slug' => $identifier]);
    $post = $stmt->fetch();

    if (!$post) {
        jsonResponse(['error' => 'Post not found'], 404);
    }

    $post['tags']       = getPostTags($db, (int) $post['id']);
    $post['categories'] = getPostCategories($db, (int) $post['id']);

    // Fetch approved comments count
    $cStmt = $db->prepare('SELECT COUNT(*) FROM comments WHERE post_id = :pid AND is_approved = 1');
    $cStmt->execute(['pid' => $post['id']]);
    $post['comments_count'] = (int) $cStmt->fetchColumn();

    jsonResponse($post);
}

// --- POST /api/posts ---
if ($method === 'POST') {
    requireAuth();

    $input = jsonInput();
    requireFields($input, ['title', 'body']);

    $title   = trim($input['title']);
    $slug    = trim($input['slug'] ?? '') ?: slugify($title);
    $body    = $input['body'];
    $summary = trim($input['summary'] ?? '');
    $author  = trim($input['author'] ?? 'SAN Operator');
    $readTime = trim($input['read_time'] ?? '5 MIN');
    $cover   = trim($input['cover_image'] ?? '');
    $status  = ($input['status'] ?? 'draft') === 'published' ? 'published' : 'draft';

    $tags       = $input['tags'] ?? [];
    $categories = $input['categories'] ?? [];

    // Auto-publish timestamp
    $publishedAt = ($status === 'published') ? date('Y-m-d H:i:s') : null;

    $stmt = $db->prepare('
        INSERT INTO posts (title, slug, summary, body, cover_image, status, author, read_time, published_at)
        VALUES (:title, :slug, :summary, :body, :cover, :status, :author, :read_time, :published_at)
    ');
    $stmt->execute([
        'title'        => $title,
        'slug'         => $slug,
        'summary'      => $summary,
        'body'         => $body,
        'cover'        => $cover,
        'status'       => $status,
        'author'       => $author,
        'read_time'    => $readTime,
        'published_at' => $publishedAt,
    ]);

    $postId = (int) $db->lastInsertId();

    if (!empty($tags)) {
        syncPostTags($db, $postId, $tags);
    }
    if (!empty($categories)) {
        syncPostCategories($db, $postId, $categories);
    }

    jsonResponse([
        'message' => 'Post created',
        'post_id' => $postId,
        'slug'    => $slug,
    ], 201);
}

// --- PUT /api/posts/{id} ---
if ($method === 'PUT' && $identifier && is_numeric($identifier)) {
    requireAuth();

    $postId = (int) $identifier;
    $input  = jsonInput();

    // Check post exists
    $stmt = $db->prepare('SELECT id FROM posts WHERE id = :id');
    $stmt->execute(['id' => $postId]);
    if (!$stmt->fetch()) {
        jsonResponse(['error' => 'Post not found'], 404);
    }

    $fields = [];
    $params = ['id' => $postId];

    foreach (['title', 'slug', 'summary', 'body', 'cover_image', 'author', 'read_time', 'status'] as $col) {
        if (array_key_exists($col, $input)) {
            $fields[] = "$col = :$col";
            $params[$col] = trim($input[$col]);
        }
    }

    // Handle status → published_at
    if (array_key_exists('status', $input)) {
        $status = $input['status'] === 'published' ? 'published' : 'draft';
        $params['status'] = $status;
        $fields[] = 'published_at = :published_at';
        $params['published_at'] = ($status === 'published') ? date('Y-m-d H:i:s') : null;
    }

    if (!empty($fields)) {
        $sql = 'UPDATE posts SET ' . implode(', ', $fields) . ' WHERE id = :id';
        $db->prepare($sql)->execute($params);
    }

    // Sync relationships
    if (array_key_exists('tags', $input)) {
        syncPostTags($db, $postId, $input['tags'] ?? []);
    }
    if (array_key_exists('categories', $input)) {
        syncPostCategories($db, $postId, $input['categories'] ?? []);
    }

    jsonResponse(['message' => 'Post updated']);
}

// --- DELETE /api/posts/{id} ---
if ($method === 'DELETE' && $identifier && is_numeric($identifier)) {
    requireAuth();

    $stmt = $db->prepare('DELETE FROM posts WHERE id = :id');
    $stmt->execute(['id' => (int) $identifier]);

    jsonResponse(['message' => 'Post deleted']);
}

// Fallback
jsonResponse(['error' => 'Method not allowed'], 405);

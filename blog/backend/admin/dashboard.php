<?php
// =============================================================================
// SAN Blog – Admin Dashboard
// =============================================================================

require_once __DIR__ . '/auth.php';
require_once __DIR__ . '/../database.php';

requireLogin();

$db   = getDB();
$msg  = $_GET['msg'] ?? '';
$page = max(1, (int) ($_GET['page'] ?? 1));
$limit = 20;
$offset = ($page - 1) * $limit;

// Handle delete
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_id'])) {
    $delId = (int) $_POST['delete_id'];
    $db->prepare('DELETE FROM posts WHERE id = :id')->execute(['id' => $delId]);
    header('Location: dashboard.php?msg=deleted');
    exit;
}

// Count posts
$countStmt = $db->query('SELECT COUNT(*) FROM posts');
$total = (int) $countStmt->fetchColumn();
$totalPages = (int) ceil($total / $limit);

// Fetch posts
$stmt = $db->prepare('SELECT * FROM posts ORDER BY created_at DESC LIMIT :limit OFFSET :offset');
$stmt->bindValue('limit', $limit, PDO::PARAM_INT);
$stmt->bindValue('offset', $offset, PDO::PARAM_INT);
$stmt->execute();
$posts = $stmt->fetchAll();
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SAN Blog Admin – Dashboard</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script>
        tailwind.config = {
            darkMode: "class",
            theme: {
                extend: {
                    colors: {
                        background: "#0f131d",
                        surface: "#1c1f2a",
                        primary: "#4cd7f6",
                        secondary: "#4edea3",
                        "on-background": "#dfe2f1",
                        "on-surface-variant": "#bcc9cd",
                        outline: "#869397",
                        "outline-variant": "#3d494c",
                        error: "#ffb4ab",
                    }
                }
            }
        }
    </script>
</head>
<body class="bg-background text-on-background min-h-screen"
      style="background-image: radial-gradient(circle at 2px 2px, rgba(6,182,212,0.03) 1px, transparent 0); background-size: 32px 32px;">

    <!-- Header -->
    <header class="border-b border-white/5 bg-surface/70 backdrop-blur-xl sticky top-0 z-50">
        <div class="max-w-6xl mx-auto px-6 h-14 flex items-center justify-between">
            <div class="flex items-center gap-6">
                <h1 class="text-primary font-bold text-lg tracking-tight">SAN Blog Admin</h1>
                <a href="dashboard.php" class="text-on-surface-variant hover:text-primary text-sm transition-colors">Posts</a>
                <a href="edit.php" class="text-on-surface-variant hover:text-primary text-sm transition-colors">New Post</a>
            </div>
            <div class="flex items-center gap-4">
                <span class="text-outline-variant text-xs font-mono"><?= htmlspecialchars($_SESSION['san_admin_username'] ?? 'operator') ?></span>
                <a href="logout.php" class="text-error/70 hover:text-error text-sm transition-colors">Logout</a>
            </div>
        </div>
    </header>

    <main class="max-w-6xl mx-auto px-6 py-8">
        <?php if ($msg === 'deleted'): ?>
            <div class="bg-red-900/20 border border-red-500/30 text-error text-sm p-3 rounded-lg mb-6">Post deleted.</div>
        <?php elseif ($msg === 'created'): ?>
            <div class="bg-green-900/20 border border-green-500/30 text-secondary text-sm p-3 rounded-lg mb-6">Post created successfully.</div>
        <?php elseif ($msg === 'updated'): ?>
            <div class="bg-green-900/20 border border-green-500/30 text-secondary text-sm p-3 rounded-lg mb-6">Post updated successfully.</div>
        <?php endif; ?>

        <div class="flex justify-between items-center mb-6">
            <h2 class="text-xl font-bold">Posts (<?= $total ?>)</h2>
            <a href="edit.php" class="bg-primary text-black font-bold px-5 py-2.5 rounded-lg hover:shadow-[0_0_15px_rgba(76,215,246,0.3)] transition-all">
                + New Post
            </a>
        </div>

        <?php if (empty($posts)): ?>
            <div class="bg-surface/50 border border-white/5 rounded-xl p-12 text-center text-on-surface-variant">
                No posts yet. Create your first one!
            </div>
        <?php else: ?>
            <div class="bg-surface/50 border border-white/5 rounded-xl overflow-hidden">
                <table class="w-full text-sm">
                    <thead>
                        <tr class="border-b border-white/5 text-outline text-left font-mono text-xs uppercase tracking-wider">
                            <th class="p-4">Title</th>
                            <th class="p-4">Status</th>
                            <th class="p-4">Author</th>
                            <th class="p-4">Created</th>
                            <th class="p-4 text-right">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach ($posts as $post): ?>
                            <tr class="border-b border-white/5 hover:bg-white/5 transition-colors">
                                <td class="p-4">
                                    <div class="font-medium"><?= htmlspecialchars($post['title']) ?></div>
                                    <div class="text-outline-variant text-xs font-mono mt-0.5">/<?= htmlspecialchars($post['slug']) ?></div>
                                </td>
                                <td class="p-4">
                                    <span class="inline-block px-2.5 py-0.5 rounded text-xs font-mono <?= $post['status'] === 'published' ? 'bg-secondary/20 text-secondary border border-secondary/30' : 'bg-yellow-900/20 text-yellow-400 border border-yellow-500/30' ?>">
                                        <?= $post['status'] ?>
                                    </span>
                                </td>
                                <td class="p-4 text-on-surface-variant"><?= htmlspecialchars($post['author']) ?></td>
                                <td class="p-4 text-on-surface-variant font-mono text-xs"><?= date('M j, Y', strtotime($post['created_at'])) ?></td>
                                <td class="p-4 text-right">
                                    <a href="edit.php?id=<?= $post['id'] ?>" class="text-primary hover:text-primary/80 mr-3 transition-colors">Edit</a>
                                    <form method="POST" class="inline" onsubmit="return confirm('Delete this post permanently?')">
                                        <input type="hidden" name="delete_id" value="<?= $post['id'] ?>" />
                                        <button type="submit" class="text-error/70 hover:text-error transition-colors">Delete</button>
                                    </form>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
            </div>

            <!-- Pagination -->
            <?php if ($totalPages > 1): ?>
                <div class="flex justify-center gap-2 mt-6">
                    <?php for ($i = 1; $i <= $totalPages; $i++): ?>
                        <a href="?page=<?= $i ?>"
                           class="px-3 py-1.5 rounded text-sm font-mono <?= $i === $page ? 'bg-primary text-black' : 'bg-white/5 text-on-surface-variant hover:bg-white/10' ?> transition-colors">
                            <?= $i ?>
                        </a>
                    <?php endfor; ?>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </main>

</body>
</html>

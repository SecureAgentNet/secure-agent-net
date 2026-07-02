<?php
// =============================================================================
// SAN Blog – Admin Login Page
// =============================================================================

require_once __DIR__ . '/auth.php';

$error = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username && $password) {
        if (doLogin($username, $password)) {
            header('Location: dashboard.php');
            exit;
        }
        $error = 'Invalid credentials';
    } else {
        $error = 'Both fields are required';
    }
}

// Already logged in → redirect to dashboard
if (isLoggedIn()) {
    header('Location: dashboard.php');
    exit;
}
?>
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>SAN Blog Admin – Login</title>
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
<body class="bg-background text-on-background min-h-screen flex items-center justify-center"
      style="background-image: radial-gradient(circle at 2px 2px, rgba(6,182,212,0.03) 1px, transparent 0); background-size: 32px 32px;">

    <div class="w-full max-w-md mx-4">
        <div class="bg-surface/70 backdrop-blur-xl border border-white/10 rounded-2xl p-8 shadow-2xl">
            <div class="text-center mb-8">
                <h1 class="text-primary font-bold text-2xl tracking-tight mb-1">SAN Blog Admin</h1>
                <p class="text-on-surface-variant text-sm">Operator authentication required</p>
            </div>

            <?php if ($error): ?>
                <div class="bg-red-900/20 border border-red-500/30 text-error text-sm p-3 rounded-lg mb-6">
                    <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>

            <form method="POST" class="space-y-5">
                <div>
                    <label class="block text-xs text-outline mb-1.5 font-mono uppercase tracking-wider">Username</label>
                    <input type="text" name="username" required autofocus
                           class="w-full bg-black/30 border border-outline-variant rounded-lg p-3 text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none transition-all"
                           placeholder="admin" />
                </div>
                <div>
                    <label class="block text-xs text-outline mb-1.5 font-mono uppercase tracking-wider">Password</label>
                    <input type="password" name="password" required
                           class="w-full bg-black/30 border border-outline-variant rounded-lg p-3 text-on-background focus:ring-1 focus:ring-primary focus:border-primary outline-none transition-all"
                           placeholder="••••••••" />
                </div>
                <button type="submit"
                        class="w-full bg-primary text-black font-bold py-3 rounded-lg hover:bg-primary/90 hover:shadow-[0_0_20px_rgba(76,215,246,0.3)] transition-all">
                    Authenticate
                </button>
            </form>

            <p class="text-outline-variant text-xs text-center mt-8 font-mono">Default: admin / changeme</p>
        </div>
    </div>

</body>
</html>

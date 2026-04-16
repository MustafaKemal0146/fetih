<?php
session_start();

// Ensure a CSRF token exists for the session
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// CSRF Check for POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF Token validation failed.");
    }
}
/**
 * SETH - Ayarlar (API anahtarları, dil, yapay zeka)
 * seth_config.json dosyasını günceller.
 */
error_reporting(E_ALL);
ini_set('display_errors', 1);

$CONFIG_FILE = __DIR__ . '/seth_config.json';
$saved = false;
$error = '';

function load_seth_config($path) {
    if (!is_file($path)) {
        return [];
    }
    $raw = @file_get_contents($path);
    if ($raw === false) return [];
    $data = @json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function save_seth_config($path, $data) {
    return file_put_contents($path, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)) !== false;
}

$config = load_seth_config($CONFIG_FILE);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $language = isset($_POST['language']) ? trim($_POST['language']) : ($config['language'] ?? 'TR');
    $use_ai = isset($_POST['use_ai']) && ($_POST['use_ai'] === '1' || $_POST['use_ai'] === 'on');
    $service = isset($_POST['service']) ? trim($_POST['service']) : ($config['service'] ?? '1');
    $api_key = isset($_POST['api_key']) ? trim($_POST['api_key']) : '';
    $viewdns_api_key = isset($_POST['viewdns_api_key']) ? trim($_POST['viewdns_api_key']) : '';

    $config['language'] = in_array($language, ['TR', 'EN']) ? $language : 'TR';
    $config['use_ai'] = $use_ai;
    $config['service'] = $service;
    if ($api_key !== '') {
        $config['api_key'] = $api_key;
    }
    if ($viewdns_api_key !== '') {
        $config['viewdns_api_key'] = $viewdns_api_key;
    }

    if (save_seth_config($CONFIG_FILE, $config)) {
        $saved = true;
    } else {
        $error = 'Config dosyası yazılamadı. Klasör yazma iznini kontrol edin.';
    }
}

$config = load_seth_config($CONFIG_FILE);
$has_api = !empty($config['api_key']);
$has_viewdns = !empty($config['viewdns_api_key']);
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SETH - Ayarlar</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Outfit:wght@400;500;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0c0c10;
            --bg-card: #12121a;
            --border: #252532;
            --accent: #e63946;
            --cyan: #00d4ff;
            --green: #10b981;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --radius: 10px;
        }
        * { box-sizing: border-box; }
        body { font-family: 'Outfit', sans-serif; background: var(--bg-dark); color: var(--text); margin: 0; padding: 24px; min-height: 100vh; }
        .wrap { max-width: 620px; margin: 0 auto; }
        h1 { font-size: 1.5rem; color: #fff; margin-bottom: 8px; }
        .back { display: inline-block; margin-bottom: 20px; color: var(--cyan); text-decoration: none; font-size: 0.9rem; }
        .back:hover { text-decoration: underline; }
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; margin-bottom: 20px; }
        .form-group { margin-bottom: 20px; }
        .form-group:last-of-type { margin-bottom: 24px; }
        .form-group label { display: block; font-size: 0.9rem; color: var(--text-muted); margin-bottom: 8px; font-weight: 500; }
        .form-group input[type="text"],
        .form-group input[type="password"],
        .form-group select {
            width: 100%;
            padding: 14px 16px;
            border: 1px solid var(--border);
            border-radius: 8px;
            background: #0d0d14;
            color: var(--text);
            font-family: 'JetBrains Mono', monospace;
            font-size: 0.9rem;
            letter-spacing: 0.02em;
            transition: border-color 0.2s, box-shadow 0.2s;
        }
        .form-group input::placeholder {
            color: #64748b;
        }
        .form-group input:focus,
        .form-group select:focus {
            outline: none;
            border-color: var(--cyan);
            box-shadow: 0 0 0 3px rgba(0, 212, 255, 0.12);
        }
        .form-group select {
            cursor: pointer;
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%2394a3b8' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10l-5 5z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 14px center;
            padding-right: 40px;
        }
        .form-group .hint { font-size: 0.8rem; color: var(--text-muted); margin-top: 6px; line-height: 1.4; }
        .checkbox-wrap { display: flex; align-items: center; gap: 10px; }
        .checkbox-wrap input { accent-color: var(--accent); }
        .btn { display: inline-block; padding: 14px 28px; border: none; border-radius: 8px; cursor: pointer; font-size: 1rem; font-family: inherit; background: var(--accent); color: #fff; font-weight: 600; transition: background 0.2s, transform 0.1s; }
        .btn:hover { background: #cc2222; }
        .btn:active { transform: scale(0.98); }
        .msg { padding: 12px; border-radius: 6px; margin-bottom: 16px; }
        .msg.ok { background: rgba(16, 185, 129, 0.15); border: 1px solid var(--green); color: var(--green); }
        .msg.err { background: rgba(230, 57, 70, 0.15); border: 1px solid var(--accent); color: var(--accent); }
    </style>
</head>
<body>
<div class="wrap">
    <a href="index.php" class="back">← Ana sayfaya dön</a>
    <h1>Ayarlar</h1>
    <p style="color: var(--text-muted); margin-bottom: 24px;">Yapay zeka API’leri ve ViewDNS API buradan yönetilir. Anahtarları değiştirmek için alanı doldurun; boş bırakırsanız mevcut değer korunur.</p>

    <?php if ($saved): ?>
        <div class="msg ok">Ayarlar kaydedildi.</div>
    <?php endif; ?>
    <?php if ($error): ?>
        <div class="msg err"><?php echo htmlspecialchars($error); ?></div>
    <?php endif; ?>

    <form method="post" action="">
        <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        <div class="card">
            <div class="form-group">
                <label>Dil / Language</label>
                <select name="language">
                    <option value="TR" <?php echo ($config['language'] ?? '') === 'TR' ? 'selected' : ''; ?>>Türkçe</option>
                    <option value="EN" <?php echo ($config['language'] ?? '') === 'EN' ? 'selected' : ''; ?>>English</option>
                </select>
            </div>

            <div class="form-group">
                <label class="checkbox-wrap">
                    <input type="checkbox" name="use_ai" value="1" <?php echo !empty($config['use_ai']) ? 'checked' : ''; ?>>
                    Yapay zeka analizi kullan (raporlarda AI özeti)
                </label>
            </div>

            <div class="form-group">
                <label>Yapay zeka servisi</label>
                <select name="service">
                    <option value="1" <?php echo ($config['service'] ?? '1') == '1' ? 'selected' : ''; ?>>Groq (önerilen)</option>
                    <option value="2" <?php echo ($config['service'] ?? '') == '2' ? 'selected' : ''; ?>>Gemini</option>
                    <option value="3" <?php echo ($config['service'] ?? '') == '3' ? 'selected' : ''; ?>>OpenAI</option>
                </select>
                <div class="hint">Groq: hızlı, ücretsiz kota. Gemini/OpenAI: kendi API anahtarınız.</div>
            </div>

            <div class="form-group">
                <label>Yapay zeka API anahtarı</label>
                <input type="password" name="api_key" placeholder="<?php echo $has_api ? '•••••••• (değiştirmek için yeni anahtar yazın)' : 'API anahtarını girin'; ?>" autocomplete="off">
                <div class="hint">Groq: console.groq.com | Gemini: ai.google.dev | OpenAI: platform.openai.com</div>
            </div>

            <div class="form-group">
                <label>ViewDNS.info API anahtarı</label>
                <input type="password" name="viewdns_api_key" placeholder="<?php echo $has_viewdns ? '•••••••• (değiştirmek için yeni anahtar yazın)' : 'viewdns.info API key'; ?>" autocomplete="off">
                <div class="hint">Cloudflare bypass için IP geçmişi. Ücretsiz: viewdns.info/api</div>
            </div>

            <button type="submit" class="btn">Kaydet</button>
        </div>
    </form>
</div>
</body>
</html>

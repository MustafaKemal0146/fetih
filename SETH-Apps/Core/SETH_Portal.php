<?php
session_start();

// Ensure a CSRF token exists for the session
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// CSRF Check for POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die("CSRF Token validation failed.");
    }
}

/**
 * SETH Operation Suite - Web Arayüzü
 * Tüm özellikler Python backend (web_Operation.py --web) ile çalışır.
 */
error_reporting(E_ALL);
ini_set('display_errors', 1);

$SCRIPT_DIR = __DIR__;
$PYTHON_SCRIPT = $SCRIPT_DIR . '/web_Operation.py';

$actions = [
    '1'  => ['Cloudflare Bypass', 'Gerçek IP bul'],
    '2'  => ['JavaScript Analizi', 'JS dosyaları ve secret'],
    '3'  => ['Kimlik Doğrulama Testi', 'Login / auth test'],
    '4'  => ['Alt Alan Adı Taraması', 'Subdomain enumeration'],
    '5'  => ['Port Taraması', 'Nmap port scan'],
    '6'  => ['Zafiyet Taraması', 'Nuclei scan'],
    '7'  => ['SQL Enjeksiyon', 'SQLMap'],
    '8'  => ['XSS Testi', 'Zafiyet taraması'],
    '9'  => ['Rapor Oluştur', 'HTML rapor'],
    '10' => ['Hedef Değiştir', 'Sadece hedefi güncelle'],
    '11' => ['Araçları Yükle', 'Gerekli toollar'],
    '12' => ['Exploit', 'Zafiyet istismarı'],
    '13' => ['Google Dork', 'Dork tarayıcı'],
    '14' => ['API Uç Noktaları', 'API test'],
    '15' => ['Dizin Taraması', 'Alt dizin belirterek tara'],
    '16' => ['DNS & Recon Özeti', 'A, AAAA, MX, TXT, NS, CNAME, SOA'],
    '17' => ['Security Headers', 'HSTS, X-Frame-Options, CSP vb.'],
    '18' => ['WAF Bypass (Hackvertor)', 'Payload encoding, WAF atlama'],
    '99' => ['TAM OTOMATİK', 'Tüm testler'],
];

$reports_dir = $SCRIPT_DIR . '/seth_reports';
$recent_reports = [];
if (is_dir($reports_dir)) {
    $files = glob($reports_dir . '/seth_report_*.html');
    usort($files, function ($a, $b) { return filemtime($b) - filemtime($a); });
    $recent_reports = array_slice($files, 0, 8);
}

$target_raw = isset($_POST['target']) ? trim($_POST['target']) : (isset($_GET['target']) ? trim($_GET['target']) : '');
$action = isset($_POST['action']) ? trim($_POST['action']) : (isset($_GET['action']) ? trim($_GET['action']) : '');
$real_ip = isset($_POST['real_ip']) ? trim($_POST['real_ip']) : (isset($_GET['real_ip']) ? trim($_GET['real_ip']) : '');
$use_cache = '1';
if (isset($_POST['no_cache']) && $_POST['no_cache']) {
    $use_cache = '0';
} elseif (isset($_POST['use_cache'])) {
    $use_cache = trim($_POST['use_cache']) === '0' ? '0' : '1';
}
$selected_ip = isset($_POST['selected_ip']) ? trim($_POST['selected_ip']) : (isset($_GET['selected_ip']) ? trim($_GET['selected_ip']) : '');
if (isset($_POST['selected_ip_manual']) && trim($_POST['selected_ip_manual']) !== '') {
    $selected_ip = trim($_POST['selected_ip_manual']);
}
$manual_ip = isset($_POST['manual_ip']) ? trim($_POST['manual_ip']) : (isset($_GET['manual_ip']) ? trim($_GET['manual_ip']) : '');

// Tek input: URL veya URL/dizin. Path varsa Dizin Taraması için kullanılır.
$target = '';
$scan_path = '';
if ($target_raw !== '') {
    $url = $target_raw;
    if (!preg_match('#^https?://#i', $url)) {
        $url = 'https://' . $url;
    }
    $p = parse_url($url);
    $scheme = isset($p['scheme']) ? $p['scheme'] : 'https';
    $host = isset($p['host']) ? $p['host'] : '';
    if ($host === '' && isset($p['path'])) {
        $host = explode('/', $p['path'])[0];
    }
    $target = $scheme . '://' . $host;
    $path = isset($p['path']) ? trim($p['path'], '/') : '';
    $scan_path = $path;
}

$output = '';
$exit_code = 0;
$prompt_type = null;
$prompt_ips = [];

function run_seth($script_dir, $python_script, $target, $action, $real_ip = '', $use_cache = '1', $selected_ip = '', $manual_ip = '', $scan_path = '') {
    $cmd = sprintf(
        'cd %s && SETH_WEB=1 SETH_USE_CACHE=%s %s %s --web --target=%s --action=%s 2>&1',
        escapeshellarg($script_dir),
        $use_cache === '0' ? '0' : '1',
        'python3',
        escapeshellarg($python_script),
        escapeshellarg($target),
        escapeshellarg($action)
    );
    if ($real_ip !== '') {
        $cmd .= ' --real-ip=' . escapeshellarg($real_ip);
    }
    if ($selected_ip !== '') {
        $cmd .= ' --selected-ip=' . escapeshellarg($selected_ip);
    }
    if ($manual_ip !== '') {
        $cmd .= ' --manual-ip=' . escapeshellarg($manual_ip);
    }
    if ($scan_path !== '' && $action === '15') {
        $cmd .= ' --scan-path=' . escapeshellarg($scan_path);
    }
    $p = popen($cmd, 'r');
    $out = '';
    if ($p) {
        while (!feof($p)) {
            $out .= fread($p, 8192);
        }
        $exit_code = pclose($p);
        return [$out, $exit_code];
    }
    return ['Error: Could not run command', 1];
}

/** Cloudflare Bypass için: çıktıyı anlık tarayıcıya yollar, sonunda tam çıktıyı döndürür */
function run_seth_stream($script_dir, $python_script, $target, $action, $real_ip = '', $use_cache = '1', $selected_ip = '', $manual_ip = '', $scan_path = '') {
    $cmd = sprintf(
        'cd %s && SETH_WEB=1 SETH_USE_CACHE=%s %s %s --web --target=%s --action=%s 2>&1',
        escapeshellarg($script_dir),
        $use_cache === '0' ? '0' : '1',
        'python3',
        escapeshellarg($python_script),
        escapeshellarg($target),
        escapeshellarg($action)
    );
    if ($real_ip !== '') {
        $cmd .= ' --real-ip=' . escapeshellarg($real_ip);
    }
    if ($selected_ip !== '') {
        $cmd .= ' --selected-ip=' . escapeshellarg($selected_ip);
    }
    if ($manual_ip !== '') {
        $cmd .= ' --manual-ip=' . escapeshellarg($manual_ip);
    }
    if ($scan_path !== '' && $action === '15') {
        $cmd .= ' --scan-path=' . escapeshellarg($scan_path);
    }
    $out = '';
    $p = @popen($cmd, 'r');
    if (!$p) {
        return ['Error: Could not run command', 1];
    }
    if (function_exists('ob_get_level')) {
        while (ob_get_level()) { ob_end_flush(); }
    }
    @ini_set('output_buffering', 'off');
    @ini_set('zlib.output_compression', false);
    while (!feof($p)) {
        $chunk = fread($p, 1024);
        if ($chunk !== false && $chunk !== '') {
            $out .= $chunk;
            echo htmlspecialchars($chunk, ENT_QUOTES, 'UTF-8');
            if (function_exists('ob_flush')) { @ob_flush(); }
            flush();
        }
    }
    $exit_code = pclose($p);
    return [$out, $exit_code];
}

$do_stream = false;
$output_already_shown = false;

if ($target !== '' && $action !== '' && file_exists($PYTHON_SCRIPT)) {
    if ($action === '10') {
        $output = "Web arayüzünde hedefi yukarıdaki 'Hedef URL' alanında değiştirip tekrar işlem seçin.";
        $exit_code = 0;
    } elseif ($action === '11') {
        $output = "Araçları yüklemek için terminalde çalıştırın: python3 web_Operation.py (ve ilk soruda Install/check tools? y/n → y)";
        $exit_code = 0;
    } else {
        $do_stream = true;
        $output = '';
        $exit_code = 0;
        set_time_limit(300);
        if (function_exists('ob_get_level')) { while (ob_get_level()) { ob_end_clean(); } }
        @ini_set('output_buffering', 'off');
        @ini_set('zlib.output_compression', false);
        @ini_set('implicit_flush', 1);
        if (function_exists('apache_setenv')) { @apache_setenv('no-gzip', '1'); }
    }
}

$ip_auto_detected = isset($ip_auto_detected) && $ip_auto_detected;

$page_title = 'SETH Operation Suite - Web';
$action_groups = [
    'Recon' => ['1', '4', '13', '16', '17'],
    'Tarama' => ['2', '3', '5', '6', '7', '8', '14'],
    'Dizin Taraması' => ['15'],
    'Rapor & Araçlar' => ['9', '10', '11'],
    'İstismar & WAF' => ['12', '18'],
    'Tam Otomatik' => ['99'],
];
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500&family=Outfit:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-dark: #0c0c10;
            --bg-card: #12121a;
            --bg-input: #0d0d14;
            --border: #252532;
            --border-focus: #e63946;
            --accent: #e63946;
            --accent-soft: #ff6b6b;
            --cyan: #00d4ff;
            --green: #10b981;
            --green-dim: #065f46;
            --text: #e2e8f0;
            --text-muted: #94a3b8;
            --radius: 10px;
            --radius-sm: 6px;
        }
        * { box-sizing: border-box; }
        body { font-family: 'Outfit', system-ui, sans-serif; background: var(--bg-dark); color: var(--text); margin: 0; min-height: 100vh; padding: 0; }
        .wrap { max-width: 1100px; margin: 0 auto; padding: 24px 20px; }
        .header { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 16px; margin-bottom: 28px; padding-bottom: 20px; border-bottom: 1px solid var(--border); }
        .logo { display: flex; align-items: center; gap: 12px; }
        .logo h1 { font-size: 1.6rem; font-weight: 700; color: #fff; margin: 0; letter-spacing: -0.02em; }
        .logo span { color: var(--accent); font-weight: 500; }
        .logo-sub { font-size: 0.8rem; color: var(--text-muted); margin-top: 2px; }
        .status-bar { display: flex; flex-wrap: wrap; gap: 16px; align-items: center; background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 18px; margin-bottom: 24px; font-size: 0.9rem; }
        .status-item { display: flex; align-items: center; gap: 8px; }
        .status-label { color: var(--text-muted); }
        .status-value { font-family: 'JetBrains Mono', monospace; color: var(--cyan); font-weight: 500; }
        .status-value.real-ip { color: var(--green); }
        .btn-copy { background: var(--border); color: var(--text-muted); border: none; padding: 6px 10px; border-radius: var(--radius-sm); cursor: pointer; font-size: 0.75rem; }
        .btn-copy:hover { background: var(--accent); color: #fff; }
        .card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 24px; margin-bottom: 20px; }
        .card h2 { font-size: 1rem; font-weight: 600; color: var(--text-muted); margin: 0 0 16px 0; text-transform: uppercase; letter-spacing: 0.05em; }
        .form-row { margin-bottom: 16px; }
        .form-row:last-of-type { margin-bottom: 0; }
        .form-row label { display: block; font-size: 0.85rem; color: var(--text-muted); margin-bottom: 6px; }
        .form-row input[type="text"] { width: 100%; max-width: 100%; padding: 12px 14px; border: 1px solid var(--border); border-radius: var(--radius-sm); background: var(--bg-input); color: var(--text); font-family: 'JetBrains Mono', monospace; font-size: 0.95rem; transition: border-color .15s; }
        .form-row input[type="text"]:focus { outline: none; border-color: var(--border-focus); }
        .form-row input[type="text"]::placeholder { color: #475569; }
        .form-inline { display: flex; flex-wrap: wrap; gap: 20px; align-items: flex-end; }
        .checkbox-wrap { display: flex; align-items: center; gap: 8px; font-size: 0.9rem; color: var(--text-muted); }
        .checkbox-wrap input { accent-color: var(--accent); }
        .ip-highlight { background: var(--green-dim); border: 1px solid var(--green); border-radius: var(--radius-sm); padding: 12px 14px; margin-top: 10px; display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; }
        .ip-highlight span { font-family: 'JetBrains Mono', monospace; color: var(--green); font-weight: 500; }
        .ip-highlight .badge { font-size: 0.7rem; background: var(--green); color: #000; padding: 4px 8px; border-radius: 4px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; }
        .btn { display: inline-flex; align-items: center; justify-content: center; padding: 11px 16px; border: none; border-radius: var(--radius-sm); cursor: pointer; font-size: 0.9rem; font-family: inherit; font-weight: 500; text-decoration: none; transition: background .15s, color .15s; }
        .btn-action { background: rgba(0, 212, 255, 0.08); color: var(--cyan); border: 1px solid rgba(0, 212, 255, 0.35); }
        .btn-action:hover { background: rgba(0, 212, 255, 0.18); }
        .btn-run { background: var(--green); color: #000; font-weight: 600; }
        .btn-run:hover { background: #0ea572; color: #000; }
        .menu-num { font-family: 'JetBrains Mono', monospace; font-size: 0.75rem; color: var(--text-muted); margin-right: 6px; }
        .output-card { margin-top: 24px; }
        .output-card h3 { font-size: 0.95rem; margin: 0 0 12px 0; color: var(--text-muted); }
        .output-box { background: #08080c; border: 1px solid var(--border); border-radius: var(--radius-sm); padding: 18px; overflow-x: auto; max-height: 70vh; overflow-y: auto; }
        .output-box pre { margin: 0; white-space: pre-wrap; word-break: break-all; font-family: 'JetBrains Mono', monospace; font-size: 0.8rem; line-height: 1.55; color: #94a3b8; }
        .prompt-box { border-color: var(--cyan); background: rgba(0, 212, 255, 0.06); padding: 28px; }
        .prompt-box h2 { font-size: 1.1rem; color: var(--cyan); margin: 0 0 8px 0; font-weight: 600; }
        .prompt-box > p { margin-bottom: 22px; }
        .prompt-box .form-row { margin-bottom: 20px; }
        .prompt-box .form-row:last-of-type { margin-bottom: 0; }
        .prompt-box label { display: block; margin-bottom: 8px; color: var(--text-muted); font-size: 0.9rem; font-weight: 500; }
        .prompt-box select,
        .prompt-box input[type="text"] {
            width: 100%; max-width: 420px; padding: 14px 16px;
            border: 1px solid var(--border); border-radius: var(--radius-sm);
            background: var(--bg-input); color: var(--text);
            font-family: 'JetBrains Mono', monospace; font-size: 1rem;
            transition: border-color .15s;
        }
        .prompt-box select:focus,
        .prompt-box input[type="text"]:focus { outline: none; border-color: var(--cyan); }
        .prompt-box select { cursor: pointer; appearance: auto; }
        .prompt-box input[type="text"]::placeholder { color: #475569; }
        .prompt-box .btn { margin-top: 20px; padding: 12px 24px; font-size: 0.95rem; }
        .section-title { font-size: 0.8rem; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; margin: 24px 0 12px 0; padding-bottom: 6px; }
        .section-title:first-of-type { margin-top: 0; }
        .dashboard-row { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }
        @media (max-width: 700px) { .dashboard-row { grid-template-columns: 1fr; } }
        .info-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px 20px; }
        .info-card h3 { font-size: 0.85rem; color: var(--cyan); margin: 0 0 10px 0; font-weight: 600; }
        .info-card ul { margin: 0; padding-left: 18px; color: var(--text-muted); font-size: 0.88rem; line-height: 1.6; }
        .info-card a { color: var(--cyan); text-decoration: none; }
        .info-card a:hover { text-decoration: underline; }
        .report-list { list-style: none; padding: 0; margin: 0; }
        .report-list li { padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 0.85rem; }
        .report-list li:last-child { border-bottom: none; }
        .report-list .date { color: var(--text-muted); font-size: 0.75rem; margin-left: 8px; }
        footer { text-align: center; margin-top: 48px; padding-top: 24px; border-top: 1px solid var(--border); color: var(--text-muted); font-size: 0.8rem; }
    </style>
</head>
<body>
<div class="wrap">
    <header class="header">
        <div class="logo">
            <div>
                <h1>SETH <span>Operation Suite</span></h1>
                <div class="logo-sub">SETH Core · Web Control Panel</div>
            </div>
        </div>
        <a href="ayarlar.php" class="btn btn-action" style="text-decoration:none;">Ayarlar (API / Dil)</a>
    </header>

    <?php if ($target !== '' || $real_ip !== '') : ?>
    <div class="status-bar">
        <?php if ($target !== '') : ?>
        <div class="status-item">
            <span class="status-label">Hedef</span>
            <span class="status-value"><?php echo htmlspecialchars($target); ?></span>
        </div>
        <?php endif; ?>
        <?php if ($real_ip !== '') : ?>
        <div class="status-item">
            <span class="status-label">Gerçek IP</span>
            <span class="status-value real-ip"><?php echo htmlspecialchars($real_ip); ?></span>
            <button type="button" class="btn-copy" data-copy="<?php echo htmlspecialchars($real_ip, ENT_QUOTES, 'UTF-8'); ?>" onclick="var t=this.getAttribute('data-copy'); if(t){navigator.clipboard.writeText(t); this.textContent='Kopyalandı'; setTimeout(function(){this.textContent='Kopyala';}.bind(this), 1500);}">Kopyala</button>
        </div>
        <?php endif; ?>
        <?php if (!empty($ip_auto_detected)) : ?>
        <div class="status-item" style="color: var(--green); font-size: 0.85rem;">✓ Cloudflare Bypass sonrası otomatik alındı</div>
        <?php endif; ?>
    </div>
    <?php endif; ?>

    <div class="dashboard-row">
        <div class="info-card">
            <h3>Önerilen işlem sırası</h3>
            <ul>
                <li>Cloudflare Bypass → Gerçek IP’yi bul</li>
                <li>DNS & Recon Özeti → Kayıtları incele</li>
                <li>Security Headers → Başlıkları kontrol et</li>
                <li>Port Taraması / Dizin Taraması → Keşif</li>
                <li>Zafiyet Taraması → Nuclei / XSS / SQL</li>
                <li>Rapor Oluştur → HTML rapor</li>
            </ul>
        </div>
        <div class="info-card">
            <h3>Son raporlar</h3>
            <?php if (count($recent_reports) > 0): ?>
            <ul class="report-list">
                <?php foreach ($recent_reports as $f): $base = basename($f); $date = date('d.m.Y H:i', filemtime($f)); ?>
                <li><a href="seth_reports/<?php echo htmlspecialchars($base); ?>" target="_blank"><?php echo htmlspecialchars($base); ?></a><span class="date"><?php echo $date; ?></span></li>
                <?php endforeach; ?>
            </ul>
            <?php else: ?>
            <p style="color: var(--text-muted); font-size: 0.88rem; margin: 0;">Henüz rapor yok. Rapor Oluştur ile ilk raporu oluşturun.</p>
            <?php endif; ?>
        </div>
    </div>

    <div id="cf-bypass-overlay" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,0.92); z-index:999999; align-items:center; justify-content:center; flex-direction:column; gap:22px; font-family: inherit;">
        <div style="color: #00d4ff; font-size: 1.25rem; font-weight: 600;">Cloudflare Bypass çalışıyor</div>
        <div style="color: #94a3b8; font-size: 1rem;">30–60 saniye sürebilir. Sayfa donmadı, lütfen bekleyin…</div>
        <div id="cf-spinner" style="width:48px; height:48px; border:4px solid #252532; border-top-color: #00d4ff; border-radius:50%; animation: cfspin 0.9s linear infinite;"></div>
    </div>
    <style>@keyframes cfspin { to { transform: rotate(360deg); } }</style>
    <div class="card">
        <form id="seth-main-form" method="post" action="">
            <div class="form-row">
                <label for="target">Hedef URL <span style="color: var(--text-muted); font-weight: 400;">(Dizin için path ekleyin: example.com/admin)</span></label>
                <input type="text" id="target" name="target" value="<?php echo htmlspecialchars($target_raw); ?>" placeholder="example.com veya example.com/admin" required>
            </div>
            <div class="form-row">
                <label for="real_ip">Gerçek IP <span style="color: var(--text-muted); font-weight: 400;">(Port / Zafiyet taramaları için; Cloudflare Bypass sonrası otomatik dolar)</span></label>
                <input type="text" id="real_ip" name="real_ip" value="<?php echo htmlspecialchars($real_ip); ?>" placeholder="Örn. 1.2.3.4 — Cloudflare Bypass çalıştırınca buraya yazılır">
                <?php if ($real_ip !== '' && !empty($ip_auto_detected)) : ?>
                <div class="ip-highlight">
                    <span><?php echo htmlspecialchars($real_ip); ?></span>
                    <span class="badge">Otomatik algılandı</span>
                </div>
                <?php endif; ?>
            </div>

            <?php foreach ($action_groups as $group_name => $nums) : ?>
            <p class="section-title"><?php echo htmlspecialchars($group_name); ?></p>
            <div class="grid" style="margin-bottom: 8px;">
                <?php foreach ($nums as $num) : if (!isset($actions[$num])) continue; $info = $actions[$num]; ?>
                <button type="submit" name="action" value="<?php echo $num; ?>" class="btn btn-action">
                    <?php echo htmlspecialchars($info[0]); ?>
                </button>
                <?php endforeach; ?>
            </div>
            <?php endforeach; ?>
            <input type="hidden" name="use_cache" value="<?php echo htmlspecialchars($use_cache); ?>">
            <input type="hidden" name="real_ip" value="<?php echo htmlspecialchars($real_ip); ?>">
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
        </form>
    </div>

    <?php
    if ($do_stream && $target !== '' && $action !== '' && $action !== '10' && $action !== '11') {
        if (function_exists('ob_get_level')) { while (ob_get_level()) { ob_end_flush(); } }
        @ini_set('output_buffering', 'off');
        @ini_set('zlib.output_compression', false);
        echo '<div class="card output-card"><h3>Çıktı (canlı)</h3><div class="output-box"><pre id="live-output">';
        if (function_exists('ob_flush')) { @ob_flush(); }
        flush();
        list($output, $exit_code) = run_seth_stream($SCRIPT_DIR, $PYTHON_SCRIPT, $target, $action, $real_ip, $use_cache, $selected_ip, $manual_ip, $scan_path);
        $output_already_shown = true;
        if (isset($exit_code) && $exit_code === 2) {
            if (preg_match('/SETH_PROMPT:SELECT_IP:(.+)$/m', $output, $m)) {
                $prompt_type = 'SELECT_IP';
                $json = trim($m[1]);
                $prompt_ips = @json_decode($json, true);
                if (!is_array($prompt_ips)) { $prompt_ips = []; }
            } elseif (strpos($output, 'SETH_PROMPT:MANUAL_IP') !== false) {
                $prompt_type = 'MANUAL_IP';
            }
        }
        if ($action === '1' && isset($exit_code) && $exit_code === 0 && $output !== '') {
            $detected_ip = null;
            if (preg_match('/Using single found IP:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/', $output, $m)) { $detected_ip = $m[1]; }
            elseif (preg_match('/Seçilen IP:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/', $output, $m)) { $detected_ip = $m[1]; }
            elseif (preg_match('/Önbellekten kullanılıyor:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/', $output, $m)) { $detected_ip = $m[1]; }
            elseif (preg_match('/Verified real IP:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/', $output, $m)) { $detected_ip = $m[1]; }
            elseif (preg_match('/Using manually entered IP[^:]*:\s*([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/', $output, $m)) { $detected_ip = $m[1]; }
            if ($detected_ip !== null) {
                $real_ip = $detected_ip;
                $ip_auto_detected = true;
            } elseif (!empty($manual_ip) && preg_match('/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/', $manual_ip)) {
                $real_ip = $manual_ip;
                $ip_auto_detected = true;
            }
        }
        $ip_auto_detected = isset($ip_auto_detected) && $ip_auto_detected;
        echo '</pre></div></div>';
        if (!empty($real_ip)) {
            echo '<script>var r=document.getElementById("real_ip");if(r)r.value=' . json_encode($real_ip) . ';</script>';
        }
    }
    ?>

    <?php if ($prompt_type === 'SELECT_IP' && count($prompt_ips) > 0) : ?>
        <div class="card prompt-box">
            <h2>Birden fazla IP bulundu</h2>
            <p style="color: var(--text-muted);">Gerçek origin IP'yi seçin; seçtiğiniz IP otomatik olarak &quot;Gerçek IP&quot; alanına yazılacak.</p>
            <form method="post" action="">
                <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
                <div class="form-row">
                    <label for="ip-select">Listeden seçin (1–<?php echo count($prompt_ips); ?>)</label>
                    <select id="ip-select" name="selected_ip">
                        <?php foreach ($prompt_ips as $i => $ip) : ?>
                            <option value="<?php echo $i + 1; ?>"><?php echo htmlspecialchars($ip); ?></option>
                        <?php endforeach; ?>
                    </select>
                </div>
                <div class="form-row">
                    <label for="ip-manual">Veya IP adresini doğrudan yazın</label>
                    <input type="text" id="ip-manual" name="selected_ip_manual" placeholder="Örn. 1.2.3.4">
                </div>
                <input type="hidden" name="target" value="<?php echo htmlspecialchars($target_raw); ?>">
                <input type="hidden" name="action" value="<?php echo htmlspecialchars($action); ?>">
                <input type="hidden" name="use_cache" value="<?php echo htmlspecialchars($use_cache); ?>">
                <input type="hidden" name="real_ip" value="<?php echo htmlspecialchars($real_ip); ?>">
                <button type="submit" class="btn btn-run">Seç ve Gerçek IP'ye yaz</button>
            </form>
        </div>
        <?php
        $sel_manual = isset($_POST['selected_ip_manual']) ? trim($_POST['selected_ip_manual']) : '';
        if ($sel_manual !== '') {
            $selected_ip = $sel_manual;
        }
        ?>
    <?php endif; ?>

    <?php if ($prompt_type === 'MANUAL_IP') : ?>
        <div class="card prompt-box">
            <h2>Manuel IP girişi</h2>
            <p style="color: var(--text-muted);">Gerçek IP otomatik bulunamadı. viewdns.info veya benzeri kaynaktan IP'yi girin; bu alan &quot;Gerçek IP&quot; kutusuna da yazılacak.</p>
            <form method="post" action="">
                <div class="form-row">
                    <label for="manual-ip">Manuel IP adresi</label>
                    <input type="text" id="manual-ip" name="manual_ip" placeholder="Örn. 1.2.3.4" required>
                </div>
                <input type="hidden" name="target" value="<?php echo htmlspecialchars($target_raw); ?>">
                <input type="hidden" name="action" value="<?php echo htmlspecialchars($action); ?>">
                <input type="hidden" name="use_cache" value="<?php echo htmlspecialchars($use_cache); ?>">
                <input type="hidden" name="real_ip" value="<?php echo htmlspecialchars($real_ip); ?>">
                <button type="submit" class="btn btn-run">Gönder ve kullan</button>
            </form>
        </div>
    <?php endif; ?>

    <?php if ($output !== '' && !$output_already_shown) : ?>
        <div class="card output-card">
            <h3>Çıktı</h3>
            <div class="output-box">
                <pre><?php echo htmlspecialchars($output); ?></pre>
            </div>
        </div>
    <?php endif; ?>

    <footer>SETH Operation Suite &copy; SETH Core · Yerel kullanım için web arayüzü</footer>
</div>
</body>
</html>

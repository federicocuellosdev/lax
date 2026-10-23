<?php
/**
 * LAX Producciones — endpoint de leads (Ferozo / DonWeb, PHP 8.x, mail() nativo).
 *
 * Recibe el POST JSON de src/lib/lead.ts (proveedor "endpoint") y lo envía por email.
 *   tramo 1 = lead nuevo · tramo 2 = detalle opcional del MISMO lead (mismo leadId), mail aparte.
 * Respuestas JSON: 200 {ok:true} · 400 · 403 · 405 · 413 · 415 · 429 · 500
 */

declare(strict_types=1);

// ===================== CONFIGURACIÓN =====================
$TO             = 'laboratoriolaxrosario@gmail.com';
// Debe ser un buzón existente en el dominio o estar autorizado en el SPF (ver docs/deploy-ferozo.md).
$FROM           = 'noreply@laboratoriolax.com';
$FROM_NAME      = 'LAX Producciones Web';
$ALLOWED_ORIGIN = 'https://producciones.laboratoriolax.com';
$ALLOW_LOCALHOST = false;         // permite http://localhost:* y 127.0.0.1 (pruebas); poné false si no lo necesitás
$MAX_BYTES      = 20 * 1024;      // tamaño máximo del body
$RATE_MAX       = 5;              // envíos permitidos por IP...
$RATE_WINDOW    = 600;            // ...en esta ventana (segundos)
$RATE_SALT      = 'Bzx00IxeCYG5JA_R39jKMCg_FA69YBai1HtNrNEjJtKA05ov'; // sal del hash de IP
$ENVELOPE_FROM  = false;          // mail(... "-f$FROM"): mejora SPF/DMARC; poné false si el hosting lo rechaza
// =========================================================

ini_set('display_errors', '0');
ini_set('log_errors', '1');

/** Campo => [etiqueta, largo máximo]. Lo que no figure acá se ignora. */
const FIELDS = [
    'nombre'         => ['Nombre', 120],
    'telefono'       => ['Teléfono / WhatsApp', 60],
    'email'          => ['Email', 160],
    'empresa'        => ['Empresa / marca', 160],
    'red'            => ['Web / Instagram', 200],
    'categoria'      => ['Categoría', 200],
    'tipoProyecto'   => ['Tipo de proyecto', 200],
    'idea'           => ['Idea / detalle del producto', 3000],
    'etapa'          => ['Etapa', 200],
    'estadoMarca'    => ['Estado de la marca', 200],
    'alcance'        => ['Alcance', 200],
    'volumen'        => ['Volumen', 200],
    'plazo'          => ['Plazo', 200],
    'formula'        => ['Fórmula', 200],
    'formulaDetalle' => ['Fórmula (detalle)', 1500],
    'marca'          => ['Marca (registro)', 200],
    'marcaNombre'    => ['Marca (nombre)', 160],
    'rotulo'         => ['Rótulo', 200],
    'contenido'      => ['Contenido neto', 120],
    'titularidad'    => ['Titularidad del RNPA', 200],
    'titularNombre'  => ['Titular (nombre / razón social)', 160],
];

function respond(int $status, array $body): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($body, JSON_UNESCAPED_UNICODE);
    exit;
}

/** Texto de una sola línea: sin CR/LF ni caracteres de control (seguro para cabeceras). */
function oneLine(string $s, int $max): string
{
    $s = preg_replace('/[\x00-\x1F\x7F]+/u', ' ', $s) ?? '';
    $s = trim(preg_replace('/\s+/u', ' ', $s) ?? '');
    return mb_substr($s, 0, $max, 'UTF-8');
}

/** Texto multilínea para el cuerpo: normaliza saltos y quita controles (salvo \n y \t). */
function multiLine(string $s, int $max): string
{
    $s = str_replace(["\r\n", "\r"], "\n", $s);
    $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $s) ?? '';
    return trim(mb_substr($s, 0, $max, 'UTF-8'));
}

/** Reenvía el payload crudo al servicio Node (break-api) que lo inyecta a Kommo. */
function forwardToBreakApi(array $payload): bool
{
    $url = 'https://break-api.onrender.com/lax/evaluar';
    $ch = curl_init($url);
    if ($ch === false) {
        return false;
    }
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => json_encode($payload, JSON_UNESCAPED_UNICODE),
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json; charset=utf-8'],
        CURLOPT_CONNECTTIMEOUT => 3,
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
    ]);
    $resp = curl_exec($ch);
    $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    return $resp !== false && $code >= 200 && $code < 300;
}

function originAllowed(string $allowed, bool $localhost): bool
{
    $src = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($src === '' && !empty($_SERVER['HTTP_REFERER'])) {
        $p = parse_url((string) $_SERVER['HTTP_REFERER']);
        $src = isset($p['scheme'], $p['host']) ? $p['scheme'] . '://' . $p['host'] . (isset($p['port']) ? ':' . $p['port'] : '') : '';
    }
    if ($src === '') {
        return false;
    }
    if (strcasecmp(rtrim($src, '/'), $allowed) === 0) {
        return true;
    }
    return $localhost && preg_match('#^http://(localhost|127\.0\.0\.1)(:\d{1,5})?$#i', $src) === 1;
}

/** Límite por IP (hash) con archivos. Devuelve false si se superó. Fallos de disco no bloquean el envío. */
function rateLimitOk(string $salt, int $max, int $window): bool
{
    $ip   = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $key  = hash('sha256', $salt . '|' . $ip);
    $dirs = [];
    if (!empty($_SERVER['DOCUMENT_ROOT'])) {
        $dirs[] = dirname(rtrim((string) $_SERVER['DOCUMENT_ROOT'], '/')) . '/lax-ratelimit'; // fuera de public_html
    }
    $dirs[] = __DIR__ . '/.ratelimit'; // respaldo dentro del web root (protegido por .htaccess)

    foreach ($dirs as $dir) {
        if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
            continue;
        }
        if (!is_writable($dir)) {
            continue;
        }
        @file_put_contents($dir . '/.htaccess', "Require all denied\n<IfModule !mod_authz_core.c>\nOrder allow,deny\nDeny from all\n</IfModule>\n", LOCK_EX);
        $fh = @fopen($dir . '/' . $key . '.json', 'c+');
        if (!$fh) {
            continue;
        }
        flock($fh, LOCK_EX);
        $now  = time();
        $list = json_decode((string) stream_get_contents($fh), true);
        $list = is_array($list) ? array_values(array_filter($list, fn($t) => is_int($t) && $t > $now - $window)) : [];
        $ok   = count($list) < $max;
        if ($ok) {
            $list[] = $now;
        }
        ftruncate($fh, 0);
        rewind($fh);
        fwrite($fh, json_encode($list));
        flock($fh, LOCK_UN);
        fclose($fh);
        // Limpieza ocasional de archivos vencidos
        if (random_int(1, 50) === 1) {
            foreach (glob($dir . '/*.json') ?: [] as $f) {
                if (filemtime($f) < $now - $window * 2) {
                    @unlink($f);
                }
            }
        }
        return $ok;
    }
    error_log('lead.php: no hay directorio escribible para el rate limit; se permite el envío');
    return true;
}

try {
    if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
        header('Allow: POST');
        respond(405, ['ok' => false, 'error' => 'method_not_allowed']);
    }
    if (!originAllowed($ALLOWED_ORIGIN, $ALLOW_LOCALHOST)) {
        respond(403, ['ok' => false, 'error' => 'forbidden_origin']);
    }
    if (stripos((string) ($_SERVER['CONTENT_TYPE'] ?? ''), 'application/json') !== 0) {
        respond(415, ['ok' => false, 'error' => 'unsupported_media_type']);
    }
    if ((int) ($_SERVER['CONTENT_LENGTH'] ?? 0) > $MAX_BYTES) {
        respond(413, ['ok' => false, 'error' => 'payload_too_large']);
    }
    $raw = file_get_contents('php://input', false, null, 0, $MAX_BYTES + 1);
    if ($raw === false || $raw === '') {
        respond(400, ['ok' => false, 'error' => 'empty_body']);
    }
    if (strlen($raw) > $MAX_BYTES) {
        respond(413, ['ok' => false, 'error' => 'payload_too_large']);
    }
    $in = json_decode($raw, true);
    if (!is_array($in) || ($in !== [] && array_keys($in) === range(0, count($in) - 1))) {
        respond(400, ['ok' => false, 'error' => 'invalid_json']);
    }

    // Honeypot: un humano lo deja vacío. A los bots se les responde 200 sin enviar nada.
    if (isset($in['bot-field']) && trim((string) (is_scalar($in['bot-field']) ? $in['bot-field'] : 'x')) !== '') {
        respond(200, ['ok' => true]);
    }

    $tramo = (string) ($in['tramo'] ?? '');
    if ($tramo !== '1' && $tramo !== '2') {
        respond(400, ['ok' => false, 'error' => 'invalid_tramo']);
    }
    $leadId = is_scalar($in['leadId'] ?? null) ? (string) $in['leadId'] : '';
    if (preg_match('/^[A-Za-z0-9_-]{1,64}$/', $leadId) !== 1) {
        respond(400, ['ok' => false, 'error' => 'invalid_lead_id']);
    }

    $d = [];
    foreach (FIELDS as $k => [$label, $max]) {
        $v = $in[$k] ?? '';
        $d[$k] = is_scalar($v) ? (in_array($k, ['idea', 'formulaDetalle'], true) ? multiLine((string) $v, $max) : oneLine((string) $v, $max)) : '';
    }
    foreach (['nombre', 'telefono', 'email'] as $req) {
        if ($d[$req] === '') {
            respond(400, ['ok' => false, 'error' => 'missing_' . $req]);
        }
    }
    if (filter_var($d['email'], FILTER_VALIDATE_EMAIL) === false || mb_strlen($d['email']) > 160) {
        respond(400, ['ok' => false, 'error' => 'invalid_email']);
    }

    // Recién ahora se consume cupo: sólo los envíos válidos cuentan
    if (!rateLimitOk($RATE_SALT, $RATE_MAX, $RATE_WINDOW)) {
        header('Retry-After: ' . $RATE_WINDOW);
        respond(429, ['ok' => false, 'error' => 'rate_limited']);
    }

    // ---- Armado del mail ----
    $enviadoEn = is_scalar($in['enviadoEn'] ?? null) ? oneLine((string) $in['enviadoEn'], 40) : '';
    $lines = [
        $tramo === '1' ? 'NUEVO LEAD — LAX Producciones (tramo 1)' : 'DETALLE COMPLETADO — LAX Producciones (tramo 2)',
        'leadId: ' . $leadId,
        'tramo: ' . $tramo,
        'Enviado (cliente): ' . ($enviadoEn ?: '-'),
        'Recibido (servidor): ' . gmdate('Y-m-d H:i:s') . ' UTC',
        str_repeat('-', 40),
    ];
    foreach (FIELDS as $k => [$label]) {
        if ($d[$k] !== '') {
            $lines[] = $label . ': ' . (str_contains($d[$k], "\n") ? "\n" . $d[$k] : $d[$k]);
        }
    }
    if (is_scalar($in['resumen'] ?? null) && trim((string) $in['resumen']) !== '') {
        $lines[] = str_repeat('-', 40);
        $lines[] = "Resumen:\n" . multiLine((string) $in['resumen'], 6000);
    }
    $body = implode("\n", $lines) . "\n";

    $subjectText = $tramo === '1'
        ? 'Nuevo lead LAX Producciones — ' . oneLine($d['nombre'], 60) . ' (tramo 1)'
        : 'Detalle de lead LAX Producciones — ' . oneLine($d['nombre'], 60) . ' (tramo 2, ' . $leadId . ')';
    $subject = '=?UTF-8?B?' . base64_encode($subjectText) . '?=';

    $fromName = '=?UTF-8?B?' . base64_encode(oneLine($FROM_NAME, 60)) . '?=';
    $headers = [
        'From: ' . $fromName . ' <' . oneLine($FROM, 160) . '>',
        'Reply-To: ' . $d['email'],            // ya validado con FILTER_VALIDATE_EMAIL (no admite CR/LF)
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=UTF-8',
        'Content-Transfer-Encoding: 8bit',
        'X-Lead-Id: ' . $leadId,
        'X-Mailer: LAX-lead-endpoint',
    ];

    $sent = $ENVELOPE_FROM
        ? mail($TO, $subject, $body, implode("\r\n", $headers), '-f' . $FROM)
        : mail($TO, $subject, $body, implode("\r\n", $headers));
    if (!$sent) {
        error_log('lead.php: mail() devolvió false (leadId=' . $leadId . ', tramo=' . $tramo . ')');
        respond(500, ['ok' => false, 'error' => 'mail_failed']);
    }

    // Forward a break-api → Kommo. Fire-and-forget: si falla, loguea y sigue (el email ya salió).
    if (!forwardToBreakApi($in)) {
        error_log('lead.php: forward a break-api/lax/evaluar falló (leadId=' . $leadId . ', tramo=' . $tramo . ')');
    }

    respond(200, ['ok' => true]);
} catch (Throwable $e) {
    error_log('lead.php: ' . $e::class . ': ' . $e->getMessage() . ' @ ' . $e->getFile() . ':' . $e->getLine());
    respond(500, ['ok' => false, 'error' => 'server_error']);
}

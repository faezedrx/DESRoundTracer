<?php
/**
 * des_round_tracer_full.php
 *
 * Single-file PHP implementation for DES round tracing, analysis and README generation.
 * - Implements DES (IP, E, S-boxes, P, PC-1, PC-2, 16 rounds)
 * - Runs multiple experiments (flip 1 bit per run) with modes: cycle, random, mixed
 * - Flip can be applied to plaintext or key (or mixed per-run)
 * - Saves per-round outputs (L and R separately) to CSV (hex)
 * - Saves run summary (final cipher, run time) to CSV
 * - Computes Hamming distances vs a baseline run and produces analysis CSVs
 * - Generates a README.md file in the output folder that explains the results and
 *   contains the "why 16 rounds and why middle rounds alone are not enough" section
 *
 * Usage: php des_round_tracer_full.php
 * Requirements: PHP 7+ (CLI). No external libs required.
 *
 * Output (folder des_outputs/):
 *  - per_round_outputs.csv
 *  - run_summary.csv
 *  - analysis_by_round.csv (avg Hamming distance per round vs baseline)
 *  - final_hamming_distribution.csv
 *  - README.md  (markdown file ready for GitHub)
 */

ini_set('memory_limit', '1024M');
date_default_timezone_set('UTC');

// ---------------- CONFIG ----------------
$plaintextHex = '0123456789ABCDEF'; // 64-bit plaintext hex
$keyHex       = '133457799BBCDFF1'; // 64-bit key hex
$runs         = 500;                // number of runs (increase for stronger statistics)
$flipMode     = 'mixed';            // 'cycle' | 'random' | 'mixed'
$flipKeyRatio = 0.5;                // for 'mixed', probability to flip key instead of plaintext
$minFlipBit   = 23;                 // low (inclusive)
$maxFlipBit   = 64;                 // high (inclusive)
$outDir       = __DIR__ . '/des_outputs';
$perRoundCsv  = $outDir . '/per_round_outputs.csv';
$summaryCsv   = $outDir . '/run_summary.csv';
$analysisCsv  = $outDir . '/analysis_by_round.csv';
$finalDistCsv = $outDir . '/final_hamming_distribution.csv';
$readmeMd     = $outDir . '/README.md';
// ----------------------------------------

// --- DES tables --- (standard)
$IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7];
$IP_INV = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25];
$E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1];
$P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4];
$PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5];
$PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32];
$SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];
$SBOX = [
    [[14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],[0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],[4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],[15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13]],
    [[15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],[3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],[0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],[13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9]],
    [[10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],[13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],[13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],[1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12]],
    [[7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],[13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],[10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],[3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14]],
    [[2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],[14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],[4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],[11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3]],
    [[12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],[10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],[9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],[4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13]],
    [[4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],[13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],[1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],[6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12]],
    [[13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],[1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],[7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],[2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11]],
];

// --------------- helpers ----------------
function hexToBitArray($hex, $bits = 64) {
    $hex = preg_replace('/[^0-9A-Fa-f]/', '', $hex);
    $bin = '';
    for ($i = 0; $i < strlen($hex); $i++) {
        $n = hexdec($hex[$i]);
        $bin .= str_pad(decbin($n), 4, '0', STR_PAD_LEFT);
    }
    if (strlen($bin) < $bits) $bin = str_pad($bin, $bits, '0', STR_PAD_LEFT);
    $bin = substr($bin, 0, $bits);
    return array_map('intval', str_split($bin));
}
function bitArrayToHex(array $bits) {
    $s = implode('', $bits);
    while (strlen($s) % 4 !== 0) $s .= '0';
    $hex = '';
    for ($i = 0; $i < strlen($s); $i += 4) {
        $n = bindec(substr($s, $i, 4));
        $hex .= strtoupper(dechex($n));
    }
    return $hex;
}
function permute(array $bits, array $table) {
    $out = [];
    foreach ($table as $pos) $out[] = $bits[$pos - 1];
    return $out;
}
function leftRotate(array $bits, $n) {
    $len = count($bits);
    $n = $n % $len;
    return array_merge(array_slice($bits, $n), array_slice($bits, 0, $n));
}
function xorBits(array $a, array $b) {
    $out = [];
    for ($i = 0; $i < count($a); $i++) $out[] = ($a[$i] ^ $b[$i]);
    return $out;
}
function intToBits($val, $len) {
    $s = str_pad(decbin($val), $len, '0', STR_PAD_LEFT);
    return array_map('intval', str_split($s));
}

function generateSubkeys($key64bitsArr, $PC1, $PC2, $SHIFTS) {
    $key56 = permute($key64bitsArr, $PC1);
    $C = array_slice($key56, 0, 28);
    $D = array_slice($key56, 28, 28);
    $subkeys = [];
    for ($r = 0; $r < 16; $r++) {
        $C = leftRotate($C, $SHIFTS[$r]);
        $D = leftRotate($D, $SHIFTS[$r]);
        $CD = array_merge($C, $D);
        $K = permute($CD, $PC2);
        $subkeys[] = $K;
    }
    return $subkeys;
}

function fFunction(array $R, array $K, $E, $SBOX, $P) {
    $expanded = permute($R, $E);
    $xored = xorBits($expanded, $K);
    $sOut = [];
    for ($i = 0; $i < 8; $i++) {
        $chunk = array_slice($xored, $i*6, 6);
        $row = ($chunk[0] << 1) | $chunk[5];
        $col = ($chunk[1] << 3) | ($chunk[2] << 2) | ($chunk[3] << 1) | $chunk[4];
        $val = $SBOX[$i][$row][$col];
        $sOut = array_merge($sOut, intToBits($val, 4));
    }
    $pout = permute($sOut, $P);
    return $pout;
}

function desEncryptTrace($plaintextHex, $keyHex, $flipBitPos = null, $flipKey = false) {
    global $IP, $IP_INV, $E, $P, $PC1, $PC2, $SHIFTS, $SBOX;
    $ptBits = hexToBitArray($plaintextHex, 64);
    $keyBits = hexToBitArray($keyHex, 64);
    if ($flipBitPos !== null) {
        $pos = $flipBitPos - 1;
        if ($pos < 0 || $pos > 63) throw new Exception("flipBitPos out of range: $flipBitPos");
        if ($flipKey) $keyBits[$pos] ^= 1; else $ptBits[$pos] ^= 1;
    }
    $ip = permute($ptBits, $IP);
    $L = array_slice($ip, 0, 32);
    $R = array_slice($ip, 32, 32);
    $subkeys = generateSubkeys($keyBits, $PC1, $PC2, $SHIFTS);
    $roundOutputs = [];
    $start = microtime(true);
    for ($r = 0; $r < 16; $r++) {
        $f = fFunction($R, $subkeys[$r], $E, $SBOX, $P);
        $newL = $R;
        $newR = xorBits($L, $f);
        $L = $newL;
        $R = $newR;
        $roundOutputs[] = ['round' => $r+1, 'L_bits' => $L, 'R_bits' => $R, 'combined' => array_merge($L,$R)];
    }
    $end = microtime(true);
    $elapsedMs = ($end - $start) * 1000.0;
    $preoutput = array_merge($R, $L);
    $cipherBits = permute($preoutput, $IP_INV);
    $cipherHex = bitArrayToHex($cipherBits);
    return ['cipher_hex' => $cipherHex, 'rounds' => $roundOutputs, 'time_ms' => $elapsedMs];
}

function hammingHex($hexA, $hexB) {
    $a = hexToBitArray($hexA, 64);
    $b = hexToBitArray($hexB, 64);
    $d = 0;
    for ($i = 0; $i < 64; $i++) $d += ($a[$i] ^ $b[$i]);
    return $d;
}

// ------------- prepare output dir and CSVs -------------
if (!is_dir($outDir)) mkdir($outDir, 0777, true);
$fpPer = fopen($perRoundCsv, 'w');
$fpSum = fopen($summaryCsv, 'w');
$fpAnalysis = fopen($analysisCsv, 'w');
$fpFinalDist = fopen($finalDistCsv, 'w');

fputcsv($fpPer, ['run_id','flip_bit_pos','flip_on_key','round','L_hex','R_hex','combined_hex','cipher_hex_after_16','run_time_ms']);
fputcsv($fpSum, ['run_id','flip_bit_pos','flip_on_key','cipher_hex_after_16','run_time_ms']);

// range
$bitRange = range($minFlipBit, $maxFlipBit);
$rangeLen = count($bitRange);

// store runs
$runsData = []; // run_id => ['flip_bit'=>, 'flip_on_key'=>, 'cipher'=>, 'time'=>, 'rounds'=> [r => combined_hex]]

for ($run = 0; $run < $runs; $run++) {
    // choose flip bit
    if ($flipMode === 'random') $flipBit = $bitRange[array_rand($bitRange)];
    else $flipBit = $bitRange[$run % $rangeLen]; // cycle
    // decide flip target
    if ($flipMode === 'mixed') {
        $flipOnKey = (mt_rand() / mt_getrandmax()) < $flipKeyRatio ? 1 : 0;
    } elseif ($flipMode === 'random' && $flipKeyRatio > 0) {
        // in random mode use flipKeyRatio as probability to flip key
        $flipOnKey = (mt_rand() / mt_getrandmax()) < $flipKeyRatio ? 1 : 0;
    } else {
        $flipOnKey = 0; // default plaintext
    }
    $trace = desEncryptTrace($plaintextHex, $keyHex, $flipBit, $flipOnKey == 1);
    $runsData[$run+1] = ['flip_bit'=>$flipBit, 'flip_on_key'=>$flipOnKey, 'cipher'=>$trace['cipher_hex'], 'time'=>$trace['time_ms'], 'rounds'=>[]];

    foreach ($trace['rounds'] as $roundEntry) {
        $Lhex = bitArrayToHex($roundEntry['L_bits']);
        $Rhex = bitArrayToHex($roundEntry['R_bits']);
        $combHex = bitArrayToHex($roundEntry['combined']);
        fputcsv($fpPer, [ $run+1, $flipBit, $flipOnKey, $roundEntry['round'], $Lhex, $Rhex, $combHex, $trace['cipher_hex'], round($trace['time_ms'],6) ]);
        $runsData[$run+1]['rounds'][$roundEntry['round']] = $combHex;
    }
    fputcsv($fpSum, [ $run+1, $flipBit, $flipOnKey, $trace['cipher_hex'], round($trace['time_ms'],6) ]);
    echo "Run " . ($run+1) . " flipBit={$flipBit} flipKey={$flipOnKey} cipher={$trace['cipher_hex']} time=" . round($trace['time_ms'],6) . " ms\n";
}

fclose($fpPer);
fclose($fpSum);

// ---------- Analysis: compute Hamming distances vs baseline (run 1) ----------
$baselineRun = 1;
if (!isset($runsData[$baselineRun])) $baselineRun = array_key_first($runsData);
$baseline = $runsData[$baselineRun]['rounds'];
$maxRound = 16;

// compute avg per round
fputcsv($fpAnalysis, ['round','avg_hamming_vs_baseline','min','max','count']);
for ($r = 1; $r <= $maxRound; $r++) {
    $vals = [];
    foreach ($runsData as $id => $info) {
        if (isset($info['rounds'][$r]) && isset($baseline[$r])) {
            $d = hammingHex($info['rounds'][$r], $baseline[$r]);
            $vals[] = $d;
        }
    }
    if (count($vals) > 0) {
        $avg = array_sum($vals) / count($vals);
        $min = min($vals);
        $max = max($vals);
        fputcsv($fpAnalysis, [$r, round($avg,4), $min, $max, count($vals)]);
    } else {
        fputcsv($fpAnalysis, [$r, '', '', '', 0]);
    }
}

// final distribution
fputcsv($fpFinalDist, ['run_id','hamming_round16_vs_baseline']);
foreach ($runsData as $id => $info) {
    if (isset($info['rounds'][16]) && isset($baseline[16])) {
        $d = hammingHex($info['rounds'][16], $baseline[16]);
        fputcsv($fpFinalDist, [$id, $d]);
    }
}

fclose($fpAnalysis);
fclose($fpFinalDist);

// ------------------ Generate README.md for GitHub ------------------
$readmeContent = <<<MD
# DES Round Tracer (PHP single-file)

این پروژه یک پیاده‌سازی کامل DES به زبان PHP برای تحلیل اثر بهمنی (avalanche) و حساسیت به تغییر ۱ بیت است. تمام عملیات، اجرای تست‌ها و تحلیل‌های پایه در یک فایل PHP قرار دارد: `des_round_tracer_full.php`.

## خروجی‌ها (پوشه `des_outputs/`)
- `per_round_outputs.csv` — هر ردیف نشان‌دهنده یک راند از یک Run است. ستون‌ها:
  - `run_id`, `flip_bit_pos`, `flip_on_key`, `round`, `L_hex`, `R_hex`, `combined_hex`, `cipher_hex_after_16`, `run_time_ms`
- `run_summary.csv` — خلاصهٔ هر Run: `run_id`, `flip_bit_pos`, `flip_on_key`, `cipher_hex_after_16`, `run_time_ms`
- `analysis_by_round.csv` — میانگین Hamming distance هر راند نسبت به baseline (run 1).
- `final_hamming_distribution.csv` — توزیع Hamming distance در راند 16 نسبت به baseline.

## اجرای سریع
```bash
php des_round_tracer_full.php
```

## پارامترهای قابل تنظیم در فایل
- `\$plaintextHex` و `\$keyHex` — مقدار پایه‌ای plaintext و key (hex 16 کاراکتری)
- `\$runs` — تعداد Runها
- `\$flipMode` — 'cycle' | 'random' | 'mixed'
- `\$flipKeyRatio` — در حالت mixed احتمال فلپ روی key
- `\$minFlipBit`, `\$maxFlipBit` — بازهٔ بیت‌هایی که تغییر می‌کنند (1..64)

## فرمت بیت‌شماری
بیت‌ها از 1 تا 64 شماره‌گذاری شده‌اند. مقدار `flip_bit_pos` در CSV بر اساس همین شماره‌هاست.

## تحلیل و تفسیر
- **اثر بهمنی (Avalanche):** انتظار می‌رود که تغییر 1 بیت در plaintext یا key بعد از چند راند منجر به تغییر قابل‌توجه در خروجی شود. این فایل خروجی‌های هر راند را ذخیره می‌کند تا بتوانی نمودار "Round vs Average #changedBits" را رسم کنی.
- **فلپ روی کلید vs plaintext:** فایل‌ها شامل ستون `flip_on_key` هستند تا بتوانی حساسیت فلپ کلید را مقایسه کنی.

## چرا DES 16 راند است و چرا راندهای وسط به تنهایی کافی نیستند
### خلاصهٔ ساده
DES با 16 راند طراحی شده تا ترکیب مناسبی از پراکندگی (diffusion) و پیچیدگی (confusion) ایجاد کند؛ راندهای ابتدایی باعث آغاز انتشار، راندهای میانی گسترش و راندهای انتهایی تثبیت نتایج را انجام می‌دهند. نگاه کردن فقط به راندهای میانی، مسیر کامل انتشار را نشان نمی‌دهد.

### توضیح فنی
- هر راند ترکیبی از جایگشت‌ها و S-box های غیرخطی است. در راندهای اولیه تغییرات محلی هستند و فقط با چند راند متوالی به پراکندگی گسترده می‌رسیم. حملاتی مثل differential cryptanalysis وابسته به ساختار چند راندی‌اند؛ حذف راندهای ابتدایی/انتهایی، مقاومت در برابر این حملات را کاهش می‌دهد.

## پیشنهادها برای پرزنتیشن در گیت‌هاب
- مقدار `\$runs` را بالا بگذار (مثلاً 1000) و نمودارهای Round vs Average Hamming (می‌توانی با اکسل یا هر ابزار رسم نمودار بسازی).
- فایل‌های CSV را ضمیمه کن و در README چند نمونه نمودار قرار بده.
- توضیح مختصر در README درباره‌ی config و interpretationِ نتایج درج کن.

## هشدار
این پیاده‌سازی برای اهداف آموزشی/تحقیقاتی است و برای استفادهٔ تولیدی توصیه نشده است.

MD;

file_put_contents($readmeMd, $readmeContent);

// -------------- finished --------------
echo "Done. Outputs in: $outDir\n";
echo "Files: per_round_outputs.csv, run_summary.csv, analysis_by_round.csv, final_hamming_distribution.csv, README.md\n";

?>

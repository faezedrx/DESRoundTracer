<?php
// des_round_tracer_full.php
// اجرای تست اثر بهمنی (Avalanche Effect) برای DES با ذخیره خروجی‌ها در CSV

ini_set('max_execution_time', 0);
ini_set('memory_limit', '512M');

date_default_timezone_set('Asia/Tehran');

// ================= تنظیمات =================
$flip_mode = 'plaintext'; // 'plaintext' یا 'key'
$runs = 100;              // تعداد اجراها
$bit_low = 23;            // کمترین بیت برای flip
$bit_high = 64;           // بیشترین بیت برای flip
$output_dir = __DIR__ . '/des_outputs';

if (!file_exists($output_dir)) {
    mkdir($output_dir, 0777, true);
}

// ================= توابع کمکی =================
function str_to_bit_array($str) {
    $bits = [];
    for ($i = 0; $i < strlen($str); $i++) {
        $bin = str_pad(decbin(ord($str[$i])), 8, '0', STR_PAD_LEFT);
        foreach (str_split($bin) as $b) $bits[] = (int)$b;
    }
    return $bits;
}

function bit_array_to_hex($bits) {
    $hex = '';
    for ($i = 0; $i < count($bits); $i += 4) {
        $nibble = array_slice($bits, $i, 4);
        $hex .= dechex(bindec(implode('', $nibble)));
    }
    return strtoupper($hex);
}

function permute($table, $input) {
    $out = [];
    foreach ($table as $pos) {
        $out[] = $input[$pos - 1];
    }
    return $out;
}

function xor_bits($a, $b) {
    return array_map(fn($x, $y) => $x ^ $y, $a, $b);
}

// ================= جداول DES =================
$IP = [58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7];
$IP_INV = [40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25];
$E = [32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1];
$P = [16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25];

$S_BOX = [
    [ [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7], [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8], [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0], [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13] ],
    [ [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10], [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5], [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15], [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9] ],
    [ [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8], [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1], [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7], [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12] ],
    [ [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15], [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9], [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4], [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14] ],
    [ [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9], [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6], [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14], [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3] ],
    [ [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11], [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8], [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6], [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13] ],
    [ [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1], [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6], [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2], [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12] ],
    [ [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7], [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2], [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8], [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11] ]
];

// ================= تابع F =================
function des_f($r, $k) {
    global $E, $P, $S_BOX;
    $er = permute($E, $r);
    $xored = xor_bits($er, $k);
    $out = [];
    for ($i = 0; $i < 8; $i++) {
        $block = array_slice($xored, $i * 6, 6);
        $row = $block[0] * 2 + $block[5];
        $col = bindec(implode('', array_slice($block, 1, 4)));
        $val = $S_BOX[$i][$row][$col];
        $bin = str_pad(decbin($val), 4, '0', STR_PAD_LEFT);
        foreach (str_split($bin) as $b) $out[] = (int)$b;
    }
    return permute($P, $out);
}

// ================= تولید کلیدها =================
function generate_keys($key_bits) {
    static $PC1 = [57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4];
    static $PC2 = [14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32];
    static $SHIFTS = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1];
    $key56 = permute($PC1, $key_bits);
    $C = array_slice($key56, 0, 28);
    $D = array_slice($key56, 28);
    $keys = [];
    foreach ($SHIFTS as $shift) {
        $C = array_merge(array_slice($C, $shift), array_slice($C, 0, $shift));
        $D = array_merge(array_slice($D, $shift), array_slice($D, 0, $shift));
        $keys[] = permute($PC2, array_merge($C, $D));
    }
    return $keys;
}

// ================= اجرای DES =================
function des_encrypt($plain_bits, $keys) {
    global $IP, $IP_INV;
    $ip = permute($IP, $plain_bits);
    $L = array_slice($ip, 0, 32);
    $R = array_slice($ip, 32);
    $rounds = [];
    for ($i = 0; $i < 16; $i++) {
        $newL = $R;
        $newR = xor_bits($L, des_f($R, $keys[$i]));
        $L = $newL;
        $R = $newR;
        $rounds[] = ['L' => $L, 'R' => $R];
    }
    $final = permute($IP_INV, array_merge($R, $L));
    return [$final, $rounds];
}

// ================= محاسبه Hamming Distance =================
function hamming_distance($a, $b) {
    $count = 0;
    for ($i = 0; $i < count($a); $i++) {
        if ($a[$i] != $b[$i]) $count++;
    }
    return $count;
}

// ================= اجرای تست‌ها =================
$csv_round = fopen("$output_dir/per_round_outputs.csv", 'w');
fputcsv($csv_round, ['Run', 'Round', 'ChangedBits', 'L_Changed', 'R_Changed']);

$csv_summary = fopen("$output_dir/run_summary.csv", 'w');
fputcsv($csv_summary, ['Run', 'FlipBit', 'HammingDistance', 'Time_ms']);

$plaintext = 'abcdefgh';
$key = '133457799BBCDFF1';

$plain_bits = str_to_bit_array($plaintext);
$key_bits = str_to_bit_array(hex2bin($key));
$keys = generate_keys($key_bits);

list($base_cipher, $base_rounds) = des_encrypt($plain_bits, $keys);

for ($r = 1; $r <= $runs; $r++) {
    $start = microtime(true);
    $flip_bit = rand($bit_low, $bit_high);
    $mod_plain = $plain_bits;
    $mod_key = $key_bits;

    if ($flip_mode == 'plaintext') {
        $mod_plain[$flip_bit % count($mod_plain)] ^= 1;
    } else {
        $mod_key[$flip_bit % count($mod_key)] ^= 1;
        $keys = generate_keys($mod_key);
    }

    list($new_cipher, $rounds) = des_encrypt($mod_plain, $keys);
    $ham_total = hamming_distance($base_cipher, $new_cipher);

    for ($i = 0; $i < 16; $i++) {
        $Ldiff = hamming_distance($base_rounds[$i]['L'], $rounds[$i]['L']);
        $Rdiff = hamming_distance($base_rounds[$i]['R'], $rounds[$i]['R']);
        fputcsv($csv_round, [$r, $i+1, $Ldiff + $Rdiff, $Ldiff, $Rdiff]);
    }

    $time_ms = round((microtime(true) - $start) * 1000, 3);
    fputcsv($csv_summary, [$r, $flip_bit, $ham_total, $time_ms]);
}

fclose($csv_round);
fclose($csv_summary);

echo "\nTests completed. CSV files saved in des_outputs/.\n";
?>



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

# اسکنر رایگان کانفیگ‌های MezaVPN روی GitHub Actions

این پروژه چند لینک Subscription استاندارد V2Ray را هر ۳۰ دقیقه دریافت می‌کند، کانفیگ‌های تکراری را **پیش از اسکن** حذف می‌کند، هر کانفیگ را واقعاً با **Xray-core** اجرا می‌کند و فقط گزینه‌های سالم و باکیفیت را در یک لینک ثابت GitHub Pages منتشر می‌کند.

## خروجی‌ها

پس از راه‌اندازی، این آدرس‌ها ساخته می‌شوند:

```text
https://USERNAME.github.io/REPOSITORY/sub.txt
https://USERNAME.github.io/REPOSITORY/sub-raw.txt
https://USERNAME.github.io/REPOSITORY/status.json
```

- `sub.txt`: ساب استاندارد Base64؛ پیشنهاد اصلی برای MezaVPN.
- `sub-raw.txt`: لینک‌های `vless://`، `vmess://`، `trojan://` و `ss://` به‌صورت خط‌به‌خط.
- `status.json`: آمار آخرین اسکن، تعداد کانفیگ‌ها، تعداد سالم‌ها و وضعیت حفاظتی.
- `state.json`: وضعیت لازم برای جلوگیری از حذف عجولانه کانفیگ‌های خوب.

## اسکن دقیقاً چه کاری انجام می‌دهد؟

1. لینک‌های موجود در Secret با نام `SUB_URLS` را دریافت می‌کند.
2. ساب خام یا Base64 را تشخیص و Decode می‌کند.
3. کانفیگ‌های دارای اتصال یکسان را، حتی اگر اسم متفاوتی داشته باشند، با Fingerprint عملکردی حذف تکراری می‌کند.
4. لینک‌های پشتیبانی‌شده را به تنظیمات واقعی Xray تبدیل می‌کند.
5. برای هر کانفیگ یک SOCKS محلی موقت و مجزا می‌سازد.
6. درخواست HTTPS واقعی را با `socks5h` از داخل همان کانفیگ عبور می‌دهد.
7. معیار Ping را از **Median زمان دریافت اولین بایت HTTPS از داخل Xray** محاسبه می‌کند؛ ICMP یا بازبودن پورت به‌تنهایی معیار نیست.
8. سه تست اولیه انجام می‌دهد. اگر یک خطای گذرا، نوسان زیاد یا Median بالاتر از محدوده Elite دیده شود، دو تست تکمیلی می‌گیرد.
9. فقط کانفیگ‌هایی را می‌پذیرد که:
   - حداقل سه پاسخ موفق داشته باشند؛
   - حداکثر یک شکست در مجموعه تست داشته باشند؛
   - نرخ موفقیت حداقل ۷۵٪ باشد؛
   - Median تأخیر از سقف گسترده سلامت `3000ms` بیشتر نباشد؛ انتخاب latency نهایی بر عهده اپ است.
   - نوسان تأخیر از `600ms` بیشتر نباشد.
10. کانفیگ‌های حداکثر `800ms` را Preferred و بقیه موارد سالم تا `3000ms` را Viable در نظر می‌گیرد.
11. روی حداکثر ۴۵۰ گزینه سالم (تمام ظرفیت خروجی)، دانلود کوچک ۲۵۶ کیلوبایتی انجام می‌دهد.
12. اگر تست سرعت اول پایین باشد، بار دوم تأیید می‌گیرد؛ فقط وقتی هر دو تست معتبر واقعاً بسیار پایین باشند، کانفیگ به علت سرعت حذف می‌شود.
13. خروجی را بر اساس تأخیر، پایداری، نوسان و سرعت مرتب می‌کند؛ وزن تأخیر عمداً بسیار بیشتر از سرعت است و کانفیگ‌های Elite همیشه اولویت بالاتری دارند.
14. برای جلوگیری از حذف اشتباهی، کانفیگ سالم قبلی در خطای مرزی یا ناتمام‌ماندن تست می‌تواند یک دوره ۳۰ دقیقه‌ای Grace داشته باشد؛ کانفیگی که در تست کامل هیچ پاسخ موفقی نداده، صرفاً با Grace فردی نگه داشته نمی‌شود.
15. اگر تعداد سالم‌ها ناگهان به‌شکل غیرعادی سقوط کند، خروجی سالم قبلی یک‌بار حفظ می‌شود تا اختلال موقت GitHub یا مقصد تست، کل ساب را خراب نکند.

## فرمت‌های پشتیبانی‌شده

- `vless://` شامل TLS، REALITY، RAW/TCP، WebSocket، gRPC، HTTPUpgrade و XHTTP
- `vmess://` مدرن با `alterId=0`
- `trojan://`
- `ss://` استاندارد SIP002 بدون Plugin خارجی

کانفیگ‌های Clash YAML، Hysteria2 URI، TUIC، WireGuard، Shadowsocks دارای Plugin و VMess قدیمی با `alterId` غیرصفر در نسخه فعلی وارد تست نمی‌شوند. حذف آن‌ها به‌عنوان «خراب» گزارش نمی‌شود؛ در آمار `unsupported` قرار می‌گیرند.

---

# راه‌اندازی مرحله‌به‌مرحله

## مرحله ۱: ساخت Repository

1. وارد GitHub شو.
2. روی **New repository** بزن.
3. نام پیشنهادی:

```text
meza-vip-scanner
```

4. Repository را روی **Public** قرار بده. اجرای استاندارد GitHub Actions برای Repository عمومی رایگان است.
5. Repository را بساز.

> لینک‌های ساب اولیه داخل Secret می‌مانند و در کد Repository قرار نمی‌گیرند؛ اما فایل خروجی GitHub Pages عمومی است.

## مرحله ۲: آپلود فایل‌های پروژه

فایل ZIP آماده را روی کامپیوتر Extract کن. سپس تمام محتویات پوشه را با همان ساختار داخل Repository قرار بده.

ساختار باید دقیقاً شبیه این باشد:

```text
.github/
  workflows/
    scan-and-publish.yml
    keepalive.yml
  last-activity.txt
.gitignore
README.md
requirements.txt
scanner.py
tests/
  test_scanner.py
  validate_xray_configs.py
```

وجود پوشه مخفی `.github` بسیار مهم است. اگر فقط فایل‌های داخل آن را بدون ساختار پوشه آپلود کنی، Workflow شناسایی نمی‌شود.

## مرحله ۳: فعال‌کردن مجوز Workflow

در Repository برو به:

```text
Settings
→ Actions
→ General
→ Workflow permissions
```

گزینه زیر را انتخاب کن:

```text
Read and write permissions
```

بعد **Save** را بزن. این مجوز برای Workflow ماهانه Keepalive لازم است. Workflow اسکن اصلی دسترسی محدود خودش را نیز تعریف کرده است.

## مرحله ۴: فعال‌کردن GitHub Pages

برو به:

```text
Settings
→ Pages
→ Build and deployment
→ Source
```

گزینه زیر را انتخاب کن:

```text
GitHub Actions
```

## مرحله ۵: واردکردن لینک‌های ساب به‌صورت Secret

برو به:

```text
Settings
→ Secrets and variables
→ Actions
→ New repository secret
```

نام Secret را دقیقاً این بگذار:

```text
SUB_URLS
```

در قسمت مقدار، هر لینک را در یک خط جدا قرار بده:

```text
https://example.com/subscription-one
https://example.com/subscription-two
https://example.com/subscription-three
```

در پایان **Add secret** را بزن.

نام Secret باید دقیقاً با حروف بزرگ `SUB_URLS` باشد. لینک‌ها را داخل فایل کد یا README قرار نده.

## مرحله ۶: اولین اجرای دستی

برو به تب:

```text
Actions
```

از سمت چپ Workflow زیر را انتخاب کن:

```text
Scan and publish MezaVPN subscription
```

سپس:

```text
Run workflow
→ Run workflow
```

پس از پایان موفق اجرای `scan` و `deploy`، آدرس اصلی تو چنین خواهد بود:

```text
https://USERNAME.github.io/meza-vip-scanner/sub.txt
```

`USERNAME` را با نام کاربری GitHub خودت جایگزین کن. اگر نام Repository را تغییر داده‌ای، بخش آخر آدرس نیز باید همان نام باشد.

## مرحله ۷: بررسی نتیجه

این فایل آمار را باز کن:

```text
https://USERNAME.github.io/REPOSITORY/status.json
```

نمونه نتیجه:

```json
{
  "configs": {
    "received_links": 1200,
    "unique_supported": 870,
    "tested": 870,
    "passed_current": 52,
    "published": 50
  },
  "quality": {
    "elite": 34,
    "acceptable": 16,
    "elite_threshold_ms": 800,
    "maximum_threshold_ms": 3000,
    "maximum_jitter_ms": 600
  },
  "safety_mode": "normal"
}
```

## مرحله ۸: اتصال به MezaVPN

اگر اپلیکیشن ساب Base64 استاندارد می‌خواهد، از این استفاده کن:

```text
https://USERNAME.github.io/REPOSITORY/sub.txt
```

اگر اپلیکیشن لینک‌ها را خط‌به‌خط Parse می‌کند، از این استفاده کن:

```text
https://USERNAME.github.io/REPOSITORY/sub-raw.txt
```

---

# تنظیمات کیفیت

تنظیمات اصلی در فایل زیر قرار دارند:

```text
.github/workflows/scan-and-publish.yml
```

## حد تأخیر عالی

```yaml
ELITE_LATENCY_MS: "800"
```

## حداکثر تأخیر قابل قبول

```yaml
MAX_LATENCY_MS: "3000"
```

## حداکثر تعداد خروجی

```yaml
MAX_OUTPUT: "450"
```

برای یک لیست کوچک‌تر و سخت‌گیرانه‌تر می‌توانی آن را روی `50` یا `60` بگذاری.

## تعداد تست‌های سرعت

```yaml
SPEED_TEST_MAX: "450"
```

فقط بهترین گزینه‌ها تست سرعت می‌شوند تا فشار و مصرف ترافیک کنترل شود.

## حجم هر نمونه سرعت

```yaml
SPEED_TEST_BYTES: "262144"
```

این مقدار برابر ۲۵۶ کیلوبایت است.

## حد بسیار پایین سرعت

```yaml
MIN_SPEED_MBPS: "0.5"
```

یک نتیجه پایین به‌تنهایی باعث حذف نمی‌شود. اسکریپت فقط در صورت دو نتیجه معتبر پایین، آن را `confirmed_slow` تشخیص می‌دهد.

## تعداد پردازش‌های موازی

```yaml
SCAN_WORKERS: "20"
```

افزایش شدید این مقدار توصیه نمی‌شود. `20` تعادل مناسبی میان زمان اجرا، RAM و فشار شبکه است.

---

# نکات مهم و محدودیت واقعی

## ۱. نتیجه GitHub معادل تست داخل ایران نیست

تست از شبکه Runner گیت‌هاب انجام می‌شود. بنابراین اسکریپت واقعاً ثابت می‌کند که کانفیگ در زمان اسکن، از شبکه GitHub به مقصد HTTPS وصل شده و کیفیت مسیرش در همان محیط مناسب بوده است؛ اما نمی‌تواند تضمین کند همان کانفیگ روی همراه اول، ایرانسل، مخابرات یا رایتل نیز دقیقاً همان نتیجه را بدهد.

برای رسیدن به کیفیت واقعی VIP در ایران، مرحله تکمیلی ایده‌آل این است که MezaVPN فقط این اطلاعات ناشناس را گزارش کند:

```text
config_fingerprint
connect_success
connection_time_ms
network_type یا ISP اختیاری
زمان تست
```

نباید UUID، Password یا خود کانفیگ ارسال شود. سپس امتیاز GitHub با نتایج واقعی کاربران ایران ترکیب می‌شود.

## ۲. DNS Leak اپلیکیشن با این اسکن ثابت نمی‌شود

در تست‌ها از `socks5h` استفاده می‌شود؛ یعنی نام دامنه مقصد به Proxy تحویل داده می‌شود و curl آن را مستقیماً روی Runner Resolve نمی‌کند. این رفتار برای خود تست صحیح است، ولی DNS Leak نهایی MezaVPN به تنظیمات Android VPNService، TUN، Private DNS، IPv6 و Routing اپ وابسته است و باید روی گوشی بررسی شود.

## ۳. GitHub زمان‌بندی لحظه‌ای تضمین نمی‌کند

Workflow برای دقیقه‌های ۷ و ۳۷ هر ساعت تنظیم شده است، اما GitHub ممکن است اجرای Cron را با تأخیر شروع کند. لینک قبلی تا زمان Deploy موفق بعدی باقی می‌ماند و پاک نمی‌شود.

## ۴. Repository عمومی بعد از بی‌فعالیتی

GitHub ممکن است Workflow زمان‌بندی‌شده Repository عمومی را پس از ۶۰ روز نبود فعالیت غیرفعال کند. فایل `keepalive.yml` ماهی یک Commit کوچک ایجاد می‌کند تا Repository فعال بماند. برای کارکرد آن، `Read and write permissions` باید فعال باشد.

## ۵. خروجی عمومی است

GitHub Pages احراز هویت ندارد. Secretهای ورودی مخفی می‌مانند، ولی هرکسی که آدرس `sub.txt` را داشته باشد می‌تواند خروجی را بخواند. `robots.txt` فقط از موتورهای جست‌وجو درخواست می‌کند صفحه را ایندکس نکنند و امنیت واقعی ایجاد نمی‌کند.

---

# خطاهای رایج

## Workflow در تب Actions دیده نمی‌شود

ساختار `.github/workflows/` اشتباه آپلود شده است یا فایل‌ها روی شاخه پیش‌فرض Repository قرار نگرفته‌اند.

## خطای `SUB_URLS secret is empty`

Secret را با نام دیگری ساخته‌ای یا مقدار آن خالی است. نام دقیق باید `SUB_URLS` باشد.

## `Pages deployment failed`

در `Settings → Pages`، Source را روی `GitHub Actions` بگذار.

## اجرای Keepalive خطای Permission می‌دهد

در `Settings → Actions → General`، گزینه `Read and write permissions` را فعال کن.

## تعداد `unsupported` زیاد است

احتمالاً ساب شامل Clash YAML، Hysteria2، TUIC، Shadowsocks Plugin یا فرمت‌های خارج از چهار پروتکل پشتیبانی‌شده است.

## خروجی ناگهان قبلی باقی مانده است

`status.json` را ببین. اگر مقدار زیر دیده شود:

```text
preserved_previous_output_once
```

یعنی افت غیرعادی تشخیص داده شده و سیستم برای جلوگیری از خالی یا خراب‌شدن ناگهانی ساب، خروجی قبلی را یک دوره حفظ کرده است.

---

# به‌روزرسانی Xray-core

نسخه Xray عمداً در Workflow ثابت شده است:

```yaml
XRAY_VERSION: "v26.3.27"
```

این کار مانع تغییر ناگهانی رفتار اسکنر با انتشار نسخه جدید می‌شود. نسخه را فقط پس از بررسی Release رسمی و اجرای موفق تست‌ها تغییر بده.

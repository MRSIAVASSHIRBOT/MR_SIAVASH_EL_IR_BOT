# MR_SIAVASH_EL_IR_BOT

ربات تلگرام مستقل با لایهٔ Cloudflare Worker و اتصال امن به MR_SIAVASH_HUB_AI از طریق Local Bridge.

## معماری پیشنهادی

- Telegram به Cloudflare Worker متصل می‌شود؛ Worker فقط لبهٔ عمومی دریافت پیام است.
- Worker فرمان‌های مجاز را پس از رمزنگاری AES-256-GCM در D1 صف می‌کند.
- Local Bridge از سیستم کاربر اتصال HTTPS خروجی به Worker برقرار می‌کند و فرمان‌ها را دریافت می‌کند.
- Bridge فقط از طریق 127.0.0.1 به API محلی HUB متصل می‌شود.
- احراز هویت Bridge با HMAC-SHA256، timestamp، nonce یک‌بارمصرف و جلوگیری از replay انجام می‌شود.
- اعتبارنامه‌های جفت‌سازی HUB فقط در OS Keyring ذخیره می‌شوند؛ هیچ fallback به فایل متنی وجود ندارد.

**هیچ پورت HUB عمومی نمی‌شود، Tunnel ایجاد نمی‌شود و HUB پشت Gateway عمومی MR_SIAVASH_AI قرار نمی‌گیرد.**

## قابلیت‌های نسخهٔ امن

- فرمان‌های /start، /help، /id و /pairinfo
- جفت‌سازی یک‌بارمصرف با /pair CODE
- بررسی وضعیت HUB با /status
- مشاهدهٔ حداکثر ۱۰ کار اخیر با /tasks فقط در صورت اعطای صریح tasks:read
- محدودسازی پیام‌ها به حساب مالک و چت خصوصی
- صف رمزنگاری‌شده، idempotency، lease و محافظت در برابر replay
- نگهداری امن اعتبارنامه‌ها با Python Keyring
- CI برای آزمون‌های Python و Cloudflare Worker

## راه‌اندازی Local Bridge

پیش‌نیازها: Python 3.10+، اجرای محلی MR_SIAVASH_HUB_AI، و یک backend معتبر OS Keyring.

```powershell
Copy-Item .env.example .env
python -m pip install -r requirements.txt
```

در فایل محلی .env مقدارهای TELEGRAM_OWNER_ID، BRIDGE_BASE_URL، HUB_API_BASE_URL و HUB_CLIENT_ID را تنظیم کن. آدرس HUB باید http://127.0.0.1:8000 باقی بماند.

Secret مشترک Worker و Bridge را در Cloudflare تنظیم کن، سپس همان مقدار را در Keyring سیستم ذخیره کن:

```powershell
python bridge.py --init-secret
python bridge.py
```

ورودی Secret هنگام راه‌اندازی مخفی است. اگر OS Keyring در دسترس نباشد، Bridge متوقف می‌شود و هیچ اعتبارنامه‌ای را در فایل plaintext ذخیره نمی‌کند.

راهنمای کامل استقرار Worker، تنظیم D1، secretها، ثبت Webhook و جفت‌سازی در cloudflare/README.md قرار دارد.

## دریافت شناسه مالک پیش از راه‌اندازی Webhook

اگر شناسه عددی تلگرام را نمی‌دانی، پیش از ثبت Webhook می‌توانی موقتاً از حالت Long Polling استفاده کنی:

1. در فایل محلی .env توکن ربات را در TELEGRAM_BOT_TOKEN قرار بده و ALLOWED_USER_IDS را خالی بگذار.
2. اجرا کن: python bot.py
3. در گفت‌وگوی خصوصی ربات، فرمان /id را بفرست و شناسه را یادداشت کن.
4. برنامه را با Ctrl+C متوقف کن.
5. شناسه را در TELEGRAM_OWNER_ID قرار بده و سپس برای راه‌اندازی Worker و ثبت Webhook اقدام کن.

این حالت فقط برای bootstrap است. اگر برای ربات Webhook فعالی وجود داشته باشد، bot.py عمداً Long Polling را شروع نمی‌کند و Webhook را حذف نمی‌کند. پس از ثبت Webhook، bot.py و Local Bridge را با هم جایگزین روش دریافت update نکن؛ برای اتصال HUB فقط bridge.py را اجرا کن.

## Long Polling محلی

فایل bot.py همچنان به‌عنوان حالت مستقل و محلی Long Polling حفظ شده است. برای یک توکن واحد، آن را هم‌زمان با Webhook فعال نکن؛ Telegram برای هر ربات یک روش دریافت update فعال دارد. پیش از تغییر روش، Webhook فعلی را بررسی کن.

## فایل قدیمی

bot_server.py از نسخهٔ قدیمی مخزن است و این نسخهٔ امن آن را اجرا یا import نمی‌کند. برای حفظ تاریخچه حذف نشده و قابلیت‌های پرخطر آن توسعه داده نمی‌شود.

## آزمون‌ها

```powershell
python -m pip install -r requirements.txt
python -m compileall -q bot.py bridge.py scripts tests
python -m unittest discover -s tests -v
npm run test:worker
```

## اسرار و امنیت

- توکن Telegram، Webhook secret، Queue encryption key و Bridge shared secret را در Git، Issue یا گفتگو قرار نده.
- Hub access/refresh tokens در OS Keyring ذخیره می‌شوند.
- Pairing code در D1 به‌صورت رمزنگاری‌شده ذخیره می‌شود.
- Bridge فقط APIهای اختصاصی Telegram HUB را فراخوانی می‌کند.
- اجرای shell، اجرای Agent، تصمیم تأیید، ایجاد Task، انتشار محتوا و ابزارهای دلخواه در این نسخه در دسترس نیست.
- مجوز پیش‌فرض status:read است؛ tasks:read فقط با رضایت صریح مالک فعال می‌شود.

## وضعیت

کد Local Bridge و صف رمزنگاری‌شده در شاخهٔ توسعه پیاده‌سازی شده‌اند؛ تا زمان اجرای CI، تنظیم secretها، ثبت webhook، جفت‌سازی واقعی و آزمون رفت‌وبرگشت تلگرام، سرویس عملیاتی و زنده محسوب نمی‌شود.

# راهنمای آزمون نهایی Port Manager V2 (برای سرور آزمایشی)

**وضعیت: آزمایشی؛ مناسب سرور اصلی نیست.** این راهنما از شاخه
`feat/portmanager-v2-roadmap` استفاده می‌کند و تا انتشار رسمی، نسخه V1
در `master/portmanager-dashboard/install.sh` بدون تغییر می‌ماند.

## پیش‌شرط

- یک ماشین **قابل حذف و بازیابی** با Ubuntu 24.04، دسترسی root از کنسول
  ارائه‌دهنده (نه صرفاً SSH)، Snapshot گرفته‌شده و IP و پورت‌های واقعی مشخص.
- بهتر است دو ماشین مستقل (واسط و مقصد) یا ۳ network namespace استفاده شود؛
  در نتیجه انتقال TCP/UDP و برگشت پاسخ مستقل آزمایش شوند.
- **NAT رمزنگاری تونل انجام نمی‌دهد.** داده‌های حساس را فقط با رمزنگاری لایه
  کاربردی جابه‌جا کنید.
- در سرور واقعی یا production از اجرای گزینه `all-except` پیش از تأیید
  دسترسی کنسول، جدول استثناها و تایمر rollback خودداری کنید.
- انتشار رسمی، تست پس از reboot کامل VM، و AT-007 purge نیاز به تأیید جداگانه دارند.

## مسیرهای نسخه

V1 اصلی (باید بدون تغییر باقی بماند):

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash
```

alias جداگانه V1 پس از merge شدن PR (در شاخه توسعه هم موجود است):

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-v1/install.sh | sudo bash
```

**نسخه V2 هنوز روی master نیست.** نصب آزمایشی با یک commit مشخص:

```bash
git clone -b feat/portmanager-v2-roadmap https://github.com/smorad3363/assistant-vps.git
cd assistant-vps
git rev-parse HEAD # مقدار SHA کامل را یادداشت کنید
sudo env PORTMANAGER2_REF="$(git rev-parse HEAD)" bash portmanager-v2/install.sh
sudo portmanager2 --version
sudo portmanager2 doctor --json
```

اگر برای تست reboot قصد فعال‌کردن سرویس‌ها را دارید، صرفاً در ماشین موقت:

```bash
sudo env PORTMANAGER2_REF="$(git rev-parse HEAD)" PORTMANAGER2_ENABLE_SERVICES=1 bash portmanager-v2/install.sh
systemctl is-enabled portmanager2-restore.service
systemctl is-enabled portmanager2-sample.timer
systemctl is-active portmanager2-sample.timer
```

## تست بدون تغییر قوانین (پیشنهادی برای شروع)

```bash
portmanager2 help
sudo portmanager2 tunnel list --json
sudo portmanager2 status --json
sudo portmanager2 limits list --json
sudo portmanager2 uninstall --dry-run
sudo iptables-save > /root/iptables-before-v2.rules
sudo tc qdisc show > /root/tc-before-v2.txt
```

## تست انتقال (فقط شبکه ایزوله)

در دستورات نمونه، نشانی‌ها و نام رابط **نمونه‌اند**؛ آنها را با IP واقعی
تخصیص‌یافته به واسط و IP قابل مسیریابی مقصد جایگزین کنید. پورت مقصد باید
قبلاً به یک سرویس TCP/UDP در ماشین مقصد اختصاص یافته باشد.

```bash
sudo portmanager2 tunnel create \
  --name qa-relay --listen-ip 192.0.2.11 --interface eth0 \
  --protocol tcp,udp --mode ports \
  --mapping 443:8443,2053:2053 --target-ip 198.51.100.10
sudo portmanager2 tunnel list --json
sudo portmanager2 report --window 1h --json
sudo portmanager2 tunnel check --json
```

زمان آزمون واقعی از یک **ماشین سوم** به IP شنونده TCP 443 و UDP 2053
بسته بفرستید و صحت مقصد، پاسخ، جهت رفت‌وبرگشت و شمارنده‌ها را کنترل کنید.
در صورت خطا، خروجی `doctor` و `logs` و `iptables -t nat -S` را
پیش از حذف تونل ذخیره کنید.

## حفاظت تغییرات پرخطر و rollback

تغییرات `all-except`، یا تغییر IP/interface، قبل از اعمال تایمر ۱۲۰ثانیه‌ای
می‌سازند و شناسه `pending_confirmation` برمی‌گردانند. اگر دسترسی سالم
است، **پیش از مهلت** آن را تأیید کنید:

```bash
sudo portmanager2 confirm UUID-OF-PENDING-CHANGE
```

اگر تأیید نکنید، باید بازگشت خودکار انجام شود. در تست عمدی مسیر دستی:

```bash
sudo portmanager2 rollback-pending UUID-OF-PENDING-CHANGE
```

قبل از هر تغییر all-except، پورت SSH واقعی، 22 و سایر سرویس‌های مدیریتی
را در `--exclude` بگذارید؛ فعال‌بودن UFW، فایروال خارجی یا پورت محلی
می‌تواند باعث رد ایمن عملیات شود.

## بازیابی و حذف

```bash
sudo portmanager2 backup create
sudo portmanager2 backup list
sudo portmanager2 uninstall --dry-run
sudo portmanager2 uninstall --yes
```

حذف عادی پوشه تنظیمات/داده V2 را **نگه می‌دارد**. برای حذف کامل داده‌ها
`sudo portmanager2 uninstall --purge` به تأیید دوم در ترمینال نیاز دارد
و فقط بعد از گرفتن Snapshot توصیه می‌شود.

**دست‌کاری دستی** زنجیره‌های `PM2_*`، فایل `systemd-owner.json` یا
`state.json` مجاز نیست: سیستم باید به‌جای تصرف منابع ناشناس خطای
`E_CONFLICT` بدهد. از `iptables -F` عمومی برای عیب‌یابی V2 استفاده نکنید.

## اطلاعات موردنیاز برای گزارش باگ

نسخه نصب‌شده، commit SHA، توزیع Linux، خروجی `doctor --json` و
`tunnel check --json`، نتیجه `systemctl status` سرویس‌های V2،
پروتکل، IP شنونده (در گزارش عمومی ناشناس‌سازی کنید)، port mapping،
شماره تست ناموفق از `TEST-MATRIX.md`، و اینکه SSH یا کنسول همچنان در
دسترس بوده را ثبت کنید. هیچ کلید خصوصی SSH یا اطلاعات ورود را ارسال نکنید.

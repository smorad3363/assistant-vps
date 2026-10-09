# دستورهای نصب دو نسخه با همان لینک اصلی

**V2 پیش‌فرض**:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash
```

**V1 قدیمی**:

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash -s -- v1
```

عبارت `sudo bash v1` نمی‌تواند ورودی piped را اجرا کند: `bash` فایل محلی
به اسم `v1` را باز می‌کند. به همین دلیل باید از `-s -- v1` استفاده شود.

**نسخهٔ جدید با همان دستور قدیمی `portmanager` اجرا می‌شود.**

هنگام نصب معمولی، اگر V1 قبلاً نصب باشد، فایل اجرایی و کران‌جاب‌های
قبلی با اثرانگشت SHA256 در `/var/lib/portmanager2/legacy-v1`
آرشیو می‌شوند. سپس مسیر `/usr/local/bin/portmanager` به V2
اختصاص پیدا می‌کند. برنامه با `portmanager2` هم قابل اجراست.

نصب با آرگومان `v1` یعنی **بازگشت واقعی به نسخهٔ قبلی**:
ابتدا V2 به‌صورت ایمن حذف می‌شود، بعد فایل اجرایی و کران قدیمی بازمی‌گردند.
اگر تونل V2 هنوز فعال باشد، نصب V1 به جای قطع ناگهانی شبکه متوقف می‌شود.
تنظیمات V2 برای نصب دوباره باقی می‌مانند.

تنظیمات V1 خودکار به تونل‌های V2 تبدیل نمی‌شوند و قواعد `tc`
قدیمی در مهاجرت بدون تأیید مدیر پاک نمی‌شوند؛ تا وقتی HTB
قدیمی فعال است، محدودکنندهٔ سرعت V2 روی آن اعمال نمی‌شود.

راه‌اندازی گراف:

```bash
sudo portmanager
sudo portmanager graph --refresh 5 --window 10m
```

زمان‌بندی نرخ پورت (فقط وقتی هیچ V1 یا clsact ناشناس نصب نیست):

```bash
sudo portmanager2 limits schedule-preview --file /tmp/schedules.json --json
sudo portmanager2 limits schedule-install --file /tmp/schedules.json --json
sudo portmanager2 limits schedule-list
sudo portmanager2 limits schedule-apply
```

ساختار فایل زمان‌بندی همان
`portmanager-v2/examples/scheduled-limits.example.json` است.
با دستور `schedule-install` موتور `tc clsact flower police` روی اینترفیس
**متعلق به V2** ساخته و سرویس نمونه‌برداری یک‌دقیقه‌ای فعال می‌شود.
اگر V1 یا فیلتر `tc` خارجی وجود داشته باشد، فرمان با `E_CONFLICT`
متوقف می‌شود و قوانین قبلی را تغییر نمی‌دهد.

این موتور هرگز `tc qdisc del dev ... root` اجرا نمی‌کند و نسخه‌های
قدیمی را بازنویسی نمی‌کند. اعمال policing ممکن است بسته‌های بیشتر از سقف
را DROP کند؛ با shaping صفیِ HTB و حداقل تأخیر یکسان نیست.

پیش از استفاده روی سرور عملیاتی: Snapshot، دسترسی کنسول مستقل،
تست reboot و تأیید سالم‌ماندن SSH الزامی است.

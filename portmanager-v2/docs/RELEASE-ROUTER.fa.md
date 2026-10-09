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

راه‌اندازی گراف:

```bash
sudo portmanager2
sudo portmanager2 graph --refresh 5 --window 10m
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

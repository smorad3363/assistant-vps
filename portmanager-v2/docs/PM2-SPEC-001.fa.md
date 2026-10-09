# سند اجرایی قطعی توسعه Port Manager V2 — Tunnel Edition

**شناسه سند:** PM2-SPEC-001  
**نسخه مشخصات:** 1.0.0  
**تاریخ مبنا:** 2026-10-09  
**زبان مرجع:** فارسی؛ نام فایل‌ها، API و CLI انگلیسی  
**وضعیت:** Specification / آماده تحویل به توسعه‌دهنده یا هوش مصنوعی؛ **هنوز پیاده‌سازی نشده است**.

> این سند یک «قرارداد پیاده‌سازی» است، نه فهرست ایده‌ها. هرجا MUST/«باید» آمده، تخطی ممنوع است. SHOULD/«بهتر است» توصیه است. هر ویژگی خارج از این قرارداد نیازمند تغییر رسمی نسخه مشخصات است. ترتیب اولویت در تعارض: **حفظ V1 و اتصال سرور > امنیت > صحت NAT و آمار > سازگاری CLI > ظاهر منو**.

## 0. هدف دقیق و محدوده

- توسعه یک محصول جدید و مستقل به نام **Port Manager V2 — Tunnel Edition** با دستور `portmanager2`.
- تجمیع مدیریت تونل مبتنی بر `iptables` شامل TCP/UDP، چند پورت و تمام پورت‌ها به‌استثنای فهرست مشخص با مانیتورینگ ترافیک، گزارش و در فاز بعد کنترل سرعت.
- باقی‌ماندن **نسخه کنونی Port Manager / V1** با دستور `portmanager`، داده‌های قبلی و دستور نصب اصلی بدون تغییر.
- قابلیت نصب فقط V1، فقط V2، یا هر دو روی یک سرور. نصب هم‌زمان به‌معنای حق دست‌کاری یکدیگر نیست.
- اجرای امن روی سرور Linux با IPv4؛ تمرکز فاز اول روی Ubuntu 22.04/24.04 و Debian 12/13. سایر توزیع‌ها فقط پس از تست و ثبت در ماتریس سازگاری.
- این ابزار **فوروارد پورت در لایه شبکه (NAT)** است و یک تونل رمزنگاری‌شده شبیه WireGuard/SSH ایجاد نمی‌کند؛ در متن UI و README این تفاوت صریح باشد.

### منابع مبنا و نقاط مرجع بازبینی

1. V1: https://github.com/smorad3363/assistant-vps/tree/master/portmanager-dashboard
2. اسکریپت نصب فعلی V1: https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh
3. منبع ایده تونل: https://github.com/azavaxhuman/IPTABLE-Tunnel-multi-port
4. commit مرجع بررسی V1 در تاریخ سند: `64842968c85f85afdad4e11c3ed4adfce65f5d22`.
5. commit مرجع بررسی Tunnel: `73fe935e86b8ae74fb83901c2624204fdf6e664d`.

در زمان شروع کار، صحت commitها و تغییر احتمالی upstream کنترل شود؛ نسخه V1 مطابق commit مرجع **فریز** شود. بدون اجازه مالک، هیچ تغییر رفتاری در V1 مجاز نیست.

## 1. قرارداد نصب، نام‌گذاری و سازگاری عقب‌رو

### 1.1 سه مسیر قطعی نصب

**دستور اصلی کنونی، همیشه V1:**

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-dashboard/install.sh | sudo bash
```

**دستور جدیدِ اختصاصی V1، هم‌رفتار با نصب اصلی:**

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-v1/install.sh | sudo bash
```

**دستور مستقل V2:**

```bash
curl -fsSL https://raw.githubusercontent.com/smorad3363/assistant-vps/master/portmanager-v2/install.sh | sudo bash
```

> دستورهای مربوط به `portmanager-v1/` و `portmanager-v2/` فقط **پس از انتشار مسیرهای جدید** معتبر هستند. این سند وجود فعلی آن‌ها را ادعا نمی‌کند.

### 1.2 قوانین اجرایی غیرقابل مذاکره

1. `portmanager-dashboard/` و فایل‌های آن، مخصوصاً `install.sh` و `portmanager.sh.gz.b64`، در این پروژه **دست‌نخورده** باقی بمانند.
2. `portmanager-v1/install.sh` صرفاً **alias-wrapper** امن برای اجرای installer موجود باشد. هیچ نصب مستقل و هیچ نسخه متفاوتی از فایل‌های V1 نسازد؛ اجرای موفق V1 با هر دو URL خروجی یکسان داشته باشد.
3. نمونه الگوریتم wrapper V1: فایل installer اصلی را با `curl -fsSL` در `mktemp` دانلود کن؛ وجود محتوای غیرخالی و سلامت دریافت را کنترل کن؛ سپس با Bash اجرا کن؛ با `trap` پاکسازی کن؛ exit code اسکریپت اصلی را حفظ کن. در صورت خطا V1 را دست نزن.
4. `/usr/local/bin/portmanager`، `/etc/portmanager`، `/var/lib/portmanager` و cron موجود V1 مطلقاً متعلق به V1 هستند؛ **V2 حق نوشتن، پاک‌کردن یا تعویضشان را ندارد**.
5. V2 فقط دستور `/usr/local/bin/portmanager2`، مسیرهای اختصاصی و سرویس‌های اختصاصی خود را مالک باشد.
6. V2 مجاز نیست خودکار V1 را نصب، حذف، restart، upgrade یا migrate کند.
7. نصب مجدد V1 از یکی از دو URL باید مثل قبل کار کند. اسکریپت جدید V1 نباید به‌صورت ضمنی V2 را نصب کند.
8. حذف V2 با `portmanager2 uninstall` باید V1 را سالم و قابل اجرا باقی بگذارد.
9. با نصب V1+V2 روی یک سرور، **هر دو برنامه اجرا می‌شوند**؛ اما فعال‌سازی هم‌زمان traffic shaping روی اینترفیس مشترک فقط طبق بخش تعارض `tc` مجاز است.
10. `master` همچنان مسیر انتشار دستورهای بالا است؛ انتشار V2 بعد از کامل شدن تست‌ها انجام شود.

### 1.3 ماتریس انتظار

| وضعیت سرور | نصب V1 | نصب V2 | رفتار مورد انتظار |
|---|---|---|---|
| خالی | موفق | ـ | فقط `portmanager` در دسترس |
| خالی | ـ | موفق | فقط `portmanager2` در دسترس |
| V1 نصب شده | ـ | موفق | V1 دقیقاً سالم؛ V2 ایزوله و آماده |
| V2 نصب شده | موفق | ـ | هیچ تنظیم V2 پاک/بازنویسی نشود؛ در صورت تعارض فعال `tc`، هشدار آشکار |
| هر دو نصب | نصب مجدد V1 | ـ | V2 سالم؛ امکان تشخیص و گزارش تغییر qdisc |
| هر دو نصب | ـ | نصب مجدد V2 | داده‌ها و قوانین V1 سالم؛ V2 بدون قانون تکراری |
| هر دو نصب | ـ | حذف V2 | فایل‌ها و قوانین V1 سالم |
| هر دو نصب | حذف V1 با ابزار قدیمی | ـ | V2 باید تغییر محیط را شناسایی کند؛ **V2 هرگز نمی‌تواند رفتار خطرناک حذف/Flush در V1 قدیمی را تضمین یا اصلاح کند** |

## 2. قرارداد خروجی و فایل‌ها

```text
assistant-vps/
├── portmanager-dashboard/                 # V1 ORIGINAL — NO CHANGES
│   ├── README.md
│   ├── install.sh
│   └── portmanager.sh.gz.b64
├── portmanager-v1/
│   ├── install.sh                          # thin alias to old installer
│   └── README.md                           # explains two V1 URLs
└── portmanager-v2/
    ├── VERSION                             # semantic version, initially 2.0.0
    ├── README.md
    ├── CHANGELOG.md
    ├── LICENSES.md
    ├── install.sh
    ├── manifest.sha256
    ├── bin/portmanager2                    # thin launcher
    ├── pm2/
    │   ├── __init__.py
    │   ├── cli.py                           # parser + exit codes
    │   ├── config.py                        # schema + atomic writes
    │   ├── validation.py                    # IP/ports/conflicts
    │   ├── discovery.py                     # route/listeners/V1/firewall
    │   ├── firewall.py                      # owned iptables chains only
    │   ├── transaction.py                   # preview/apply/rollback
    │   ├── accounting.py                    # conntrack-aware per-tunnel counters
    │   ├── sampler.py                       # monotonic deltas + SQLite
    │   ├── bandwidth.py                     # safe tc integration
    │   ├── dashboard.py                     # terminal UI
    │   ├── persistence.py                   # restore on boot
    │   ├── diagnostics.py                   # doctor/status/logs
    │   └── errors.py                        # stable error codes
    ├── systemd/
    │   ├── portmanager2-restore.service
    │   ├── portmanager2-sample.service
    │   └── portmanager2-sample.timer
    ├── schemas/config-v1.schema.json
    ├── tests/
    │   ├── unit/
    │   ├── integration/
    │   ├── networkns/
    │   ├── regression/
    │   └── fixtures/
    └── docs/
        ├── ARCHITECTURE.md
        ├── FIREWALL-OWNERSHIP.md
        ├── INSTALL-ROLLBACK.md
        ├── CLI.md
        ├── TROUBLESHOOTING.md
        └── TEST-MATRIX.md
```

**زبان V2:** Python 3.10+ با کتابخانه استاندارد (argparse, ipaddress, sqlite3, json, fcntl, subprocess, logging)، installer و launcher کوتاه Bash. **هیچ کد اصلی V2 نباید به فایل Base64 فشرده و غیرقابل بازبینی تبدیل شود.** وابستگی‌های سیستمی حداقل: `iptables`, `iptables-save`, `iptables-restore`, `ip`, `ss`, `tc`, `systemctl`, `flock` یا معادل Python آن. `conntrack` برای نمایش شمار اتصالات اختیاری با نمایش `N/A` هنگام نبود وابستگی. هیچ ابزار جانبی بدون ثبت در README اضافه نشود.

### 2.1 مسیرهای نصب روی سرور

```text
/usr/local/bin/portmanager2
/opt/portmanager2/releases/<version>/...
/opt/portmanager2/current -> releases/<version>
/etc/portmanager2/config.json
/etc/portmanager2/owner.json
/var/lib/portmanager2/state.json
/var/lib/portmanager2/traffic.sqlite3
/var/lib/portmanager2/backups/<timestamp>/
/var/log/portmanager2/portmanager2.log
/run/lock/portmanager2.lock
/etc/systemd/system/portmanager2-restore.service
/etc/systemd/system/portmanager2-sample.service
/etc/systemd/system/portmanager2-sample.timer
```

- برنامه‌های اجرایی و پیکربندی root-owned، فاقد مجوز نوشتن کاربران دیگر باشند. JSON حاوی IPها و قوانین ممکن است حساس باشد؛ فایل‌های `/etc/portmanager2` با mode `0600` یا حداقل دسترسی لازم.
- `install.sh` پوشه موقت نسخه را می‌سازد، checksum فایل‌ها را چک می‌کند، صحت Python را می‌سنجد، سپس symlink `current` را **اتمیک** جابه‌جا می‌کند؛ هنگام failure به نسخه قبلی بازمی‌گردد.
- نصب V2 با نصب مجدد، config و database را حفظ می‌کند و بدون تغییر موجودیت tunnel، قانون duplicate نمی‌سازد.
- uninstall بدون `--purge`: سرویس‌های V2 غیرفعال و قوانین مالکیتی V2 حذف شوند، اما config/data به‌صورت پیش‌فرض برای بازیابی باقی بمانند. `--purge` فقط داده‌های V2 را پس از تأیید دوباره پاک کند؛ هرگز داده‌های V1 را حذف نکند.

## 3. حدود پشتیبانی و موارد خارج از محدوده

### MUST در نسخه 2.0.0

- CLI و منوی متنی، ساخت/نمایش/ویرایش/حذف/فعال/غیرفعال کردن تونل IPv4 TCP/UDP.
- چند پورت با نگاشت یک‌به‌یک یا تغییر پورت؛ حالت all-except با حفاظت اجباری پورت مدیریتی.
- نگهداری ruleها پس از reboot با `systemd` و apply امن idempotent.
- آمار هر تونل در FORWARD بر مبنای tuple اصلی conntrack و نرخ لحظه‌ای و گزارش 1h/24h/7d.
- پیش‌نمایش، شناسایی تعارض، حفظ V1، restore، rollback، تشخیص خرابی و log.
- تشخیص و گزارش تعارض traffic shaping؛ **در 2.0.0 هیچ shaping جدیدی از طریق V2 اعمال نشود**. فرمان‌های `limits set/remove` در حضور V1/مالک tc خارجی `E_CONFLICT` و در غیر این صورت `E_UNSUPPORTED` بدهند. قابلیت عملی محدودسازی سرعت V2 فقط در **2.1.x** با ownership و تست throughput عرضه شود.

### SHOULD در 2.1.x، **الزام 2.0.0 نیست**

- محدودسازی سرعت واقعیِ مستقل برای هر تونل با tc در حالت مالکیت انحصاری اینترفیس و تست throughput.
- سهمیه حجمی، هشدار مصرف، export CSV/JSON، سلامت مقصد و هشدار اختلال.

### خارج از MVP

IPv6 DNAT، سرویس وب، reverse proxy لایه 7، VPN رمزنگاری‌شده، مدیریت از راه دورِ چند سرور، کنترل کاربران، auto-upgrade، تغییر خودکار UFW/firewalld، مهاجرت تنظیمات V1، ادعای تضمین 100% دقت حسابداری ترافیک در حضور offloadهای متفاوت. این موارد **نباید بی‌صدا شبیه‌سازی شوند**؛ فرمان مربوطه خطای `E_UNSUPPORTED` دهد.

## 4. قرارداد CLI: نحو ثابت و معنای قطعی

```text
portmanager2                                  # interactive TUI
portmanager2 --version
portmanager2 help
portmanager2 doctor [--json]
portmanager2 status [--json]
portmanager2 tunnel list [--json]
portmanager2 tunnel show <id> [--json]
portmanager2 tunnel create --name NAME --listen-ip IPV4 --interface IFACE \
  --protocol tcp|udp|tcp,udp --mode ports --mapping 80:8080,443:8443 \
  --target-ip IPV4 [--dry-run]
portmanager2 tunnel create --name NAME --listen-ip IPV4 --interface IFACE \
  --protocol tcp|udp|tcp,udp --mode all-except --exclude 22,10022 \
  --target-ip IPV4 --ack-all-ports [--dry-run]
portmanager2 tunnel update <id> [same tunnel configuration flags] [--dry-run]
portmanager2 tunnel enable <id> [--dry-run]
portmanager2 tunnel disable <id> [--dry-run]
portmanager2 tunnel delete <id> [--yes] [--dry-run]
portmanager2 tunnel apply [--dry-run]
portmanager2 tunnel check [--json]
portmanager2 confirm <change-id>                # cancel only the associated 120-second auto-rollback
portmanager2 live [--interval 1] [--tunnel ID]
portmanager2 report --window 1h|24h|7d [--json]
portmanager2 limits list [--json]
portmanager2 limits set --tunnel ID --up 20mbit --down 50mbit [--dry-run]
portmanager2 limits remove --tunnel ID [--dry-run]
portmanager2 sample                            # systemd timer only; safe manual
portmanager2 restore                           # idempotent boot re-apply
portmanager2 backup create
portmanager2 backup list
portmanager2 backup restore <backup-id> [--dry-run]
portmanager2 logs [--lines 100]
portmanager2 uninstall [--purge] [--yes] [--dry-run]
```

**تعریف دقیق:**

- `--mapping A:B` پورت ورودی A را به پورت B در IP مقصد منتقل می‌کند؛ `A` یا `B` در محدوده 1..65535. `--mapping 443:443,80:8080` مجاز است؛ تکرار پورت ورودی در یک پروتکل ممنوع است.
- همه مقادیر `--protocol` فقط `tcp`, `udp`, `tcp,udp` با ترتیب همین الگو. V2 همیشه هر دو نوع ترافیک را در صورت انتخاب بررسی کند.
- `--mode ports` به `--mapping` احتیاج دارد و با `--exclude` ترکیب نمی‌شود.
- `--mode all-except` به `--exclude` احتیاج دارد، نگاشت پورت مجاز ندارد، و فقط TCP/UDP را forward می‌کند؛ بدون `--ack-all-ports` خطای اعتبارسنجی می‌دهد. تمام پورت‌های غیرمستثنا شماره پورت اصلی خود را حفظ می‌کنند.
- `--name`: 1..64 کاراکتر شامل حرف لاتین، رقم، `_` و `-`؛ منحصر‌به‌فرد (case-insensitive).
- `id` یک UUIDv4 پایدار و مستقل از نام است؛ تغییر نام UUID را تغییر نمی‌دهد.
- `--listen-ip` باید یکی از IPv4های اختصاص‌یافته به سرور باشد؛ `--interface` باید موجود و UP باشد، مگر عملیات `--dry-run` که اخطار بدهد.
- `--target-ip` باید IPv4 unicast معتبر باشد؛ IP حلقه‌ای، multicast، unspecified و برابر IP ورودی یا IP محلیِ خطرناک رد شود. مقصد با `ip route get` از نظر route و loop بررسی گردد. مقصد خصوصی در صورت وجود route معتبر مجاز است.
- همه عملیات read-only به کاربر عادی مجازند **فقط در حد مجوز فایل‌ها و سیستم‌عامل**؛ تغییر rules و نصب نیازمند root هستند.
- `--json` خروجی پایدار ماشین‌خوان؛ بدون banner، رنگ ANSI یا خط اضافه.
- `--dry-run` هرگز سیستم، config، DB یا rule را تغییر ندهد؛ فقط پیش‌نمایش با کد خروجی متناسب.
- `--yes` صرفاً confirmation کاربر را حذف می‌کند؛ **حق عبور از اعتبارسنجی امنیتی ندارد**.
- `tunnel update <id>` باید **تمام گزینه‌های اجباری دستور create** را مجدداً دریافت کند و جایگزینی کامل پیکربندی باشد، نه patch ضمنی؛ ID تغییر نمی‌کند. در منوی تعاملی، مقادیر قبلی از پیش پر شده‌اند. عدم ارسال پارامتر اجباری => `E_VALIDATION`.
- `tunnel delete` پیکربندی و chain rules آن تونل را حذف می‌کند؛ آمار تاریخی تحت UUID نگهداری می‌شود مگر purge جداگانه داده.
- `report` در صورت نبود sample، JSON معتبر با `coverage_seconds=0` و مقادیر `null` به‌جای سرعت ساختگی برگرداند.
- `limits list` در 2.0.0 فقط وضعیت `supported=false`, `reason="planned_for_2.1"` و فهرست خالی را برمی‌گرداند؛ **وجود گزینه منو به معنی اعمال واقعی limit نیست**.

### 4.1 کدهای خروج ثابت

| exit | کد خطای ماشینی | معنا |
|---|---|---|
| 0 | `OK` | موفق |
| 2 | `E_VALIDATION` | ورودی یا schema نامعتبر |
| 3 | `E_PERMISSION` | نیاز به root/مجوز |
| 4 | `E_DEPENDENCY` | وابستگی سیستمی ناقص |
| 5 | `E_CONFLICT` | تداخل SSH، NAT، firewall، V1 یا qdisc |
| 6 | `E_APPLY` | خطا در اعمال rule یا service |
| 7 | `E_ROLLBACK` | rollback ناقص؛ هشدار بحرانی و مسیر بازیابی |
| 8 | `E_UNSUPPORTED` | پلتفرم یا قابلیت پشتیبانی‌نشده |
| 9 | `E_LOCKED` | عملیات هم‌زمان دیگری در حال اجرا |

در خروجی JSON فیلدهای `ok`, `code`, `message`, `details`, `request_id` ثابت باشند.

## 5. ساختار داده و پایداری

`/etc/portmanager2/config.json` نمونه معتبر:

```json
{
  "schema_version": 1,
  "generation": 1,
  "tunnels": [
    {
      "id": "9eb517af-28c9-4a65-b038-21cf116f9868",
      "name": "iran-to-remote",
      "enabled": true,
      "mode": "ports",
      "listen_ip": "198.51.100.10",
      "interface": "eth0",
      "protocols": ["tcp", "udp"],
      "mapping": [
        {"listen_port": 443, "target_port": 8443},
        {"listen_port": 2053, "target_port": 2053}
      ],
      "exclude": [],
      "target_ip": "203.0.113.20"
    }
  ]
}
```

> IPها در نمونه از بازه‌های مستندسازی هستند و به‌عنوان تنظیم واقعی استفاده نمی‌شوند.

- `generation` با هر تغییر موفق پیکربندی +1 شود؛ `config.json` با temp + `fsync` + atomic `rename` نوشته شود.
- `schema_version` نامعتبر یا بالاتر از نسخه پشتیبانی‌شده => برنامه در حالت تغییر **fail closed**؛ فقط نمایش/backup مجاز.
- یک فایل `state.json` شامل `desired_generation`, `applied_generation`, `last_error`, `applied_at`, `backend`, `interface_snapshot`.
- SQLite فقط با schema migration نسخه‌دار، transaction، WAL و ثبت دوره‌های زمانی UTC؛ زمان UI به timezone سیستم نمایش داده شود.
- جداول حداقل: `tunnels`, `samples`, `daily_rollups`, `events`, `schema_migrations`.
- هر sample شامل `timestamp_utc`, `tunnel_id`, `protocol`, `rx_bytes_total`, `tx_bytes_total`, `rx_delta`, `tx_delta`, `counter_epoch`, `interval_seconds`.
- تعریف آمار ثابت: از دید **کلاینت ورودی تونل**، `UPLOAD` = بسته‌های ORIGINAL از کلاینت به مقصد، `DOWNLOAD` = بسته‌های REPLY از مقصد به کلاینت. این نام‌گذاری در تمام UI/API یکسان باشد.
- خروجی `MB` باید واحد ده‌دهی 10^6 و `MiB` واحد دودویی 2^20 باشد؛ سرعت `Mbit/s` ده‌دهی است.
- بازنشانی counters هنگام reboot یا بازسازی rule: افزایش `counter_epoch` و محاسبه delta از صفر، نه اعداد منفی یا spike ساختگی. گزارش تاریخی باید rollup قبلی را حفظ کند.
- بازه‌های `1h, 24h, 7d` شامل نمونه‌هایی باشند که timestamp آن‌ها داخل پنجره UTC است؛ در خروجی میزان coverage نیز اعلام شود.

## 6. موتور شبکه و مالکیت iptables

### 6.1 اصل مالکیت

- V2 باید فقط زنجیره‌های خودش را با نام‌های ثابت و منحصربه‌فرد بسازد؛ مثال (حداکثر طول مجاز نام chain در backend چک شود):
  - `PM2_NAT_PRE` در `nat`
  - `PM2_NAT_POST` در `nat`
  - `PM2_FORWARD` در `filter`
  - `PM2_ACCOUNT` در `mangle`
- ورود از chainهای استاندارد به chainهای V2 فقط با hookهای لازم و هر hook حداکثر **یک بار** باشد: `PREROUTING`، `POSTROUTING`، `FORWARD` و در mangle `FORWARD`.
- ruleهای داخل chains متعلق به V2 باید `-m comment --comment "pm2:<tunnel-uuid>:<purpose>"` داشته باشند. هویت مالکیت در metadata و comment ثبت گردد؛ صرف شباهت rule به V2 مجوز حذف نیست.
- V2 **هرگز** `iptables -F`، `iptables -X`، `iptables -P ...` یا `iptables-restore` بدون محدوده مالکیتی روی کل ruleset اجرا نکند.
- V2 مطلقاً `iptables-persistent`، فایل `/etc/iptables/rules.v4` و زنجیره V1 به نام `PORTMANAGER_ACCT` را تغییر ندهد.
- قبل از تغییر، snapshot فقط-خواندنی از ruleset و manifest مالکیت بگیرد؛ اعمال و rollback فقط chain/hookهای خودش را لمس کنند. Snapshot کامل صرفاً برای تشخیص/بازیابی دستی ثبت شود؛ خودکار روی قوانین سایر برنامه‌ها restore نشود.
- IPv4 فقط؛ در حضور backend `iptables-nft` یا `iptables-legacy` اجرای V2 به همان backend انتخاب‌شده سیستم محدود باشد؛ backend در هر اجرا چک شود، تغییر backend زیر پا باعث `E_CONFLICT` و عدم تغییر شود.
- تمام فراخوانی‌ها با `subprocess` و آرایه آرگومان‌ها، **بدون** `shell=True`؛ همه دستورات `iptables` با قابلیت waiting for xtables lock اجرا شوند.

### 6.2 الگوریتم DNAT و SNAT

1. برای هر تونل enabled، ابتدا تعارض پورت‌ها و قوانین NAT قبلی بررسی شود.
2. هر rule DNAT به **آی‌پی ورودی مشخص**، **اینترفیس ورودی مشخص**، **پروتکل مشخص** و **پورت مشخص یا الگوی all-except** محدود شود.
3. برای `ports`: نگاشت مستقل هر `listen_port -> target_ip:target_port` ایجاد شود؛ TCP و UDP هرکدام مستقل.
4. برای `all-except`: برای هر پروتکل تمام پورت‌های مستثنا داخل chain اختصاصی V2 به مقصد `RETURN` برسند؛ سپس فقط ترافیک به listen-ip/interface با `DNAT --to-destination target_ip` منتقل شود تا **پورت اصلی حفظ شود**. استثناهای بیشتر از 15 عدد بدون محدودیت `multiport` شکسته شوند؛ راهکار قطعی MVP: **یک rule مستقل به‌ازای هر پورت مستثنا**.
5. POSTROUTING با MASQUERADE یا SNAT **فقط برای همان اتصال‌های DNAT‌شده توسط V2** ایجاد شود؛ تطبیق باید بر اساس tuple اولیه conntrack (IPv4 ورودی/پروتکل/پورت ORIGINAL) و مقصد نهایی باشد، نه یک `-j MASQUERADE` عمومی.
6. در `filter/FORWARD` فقط جریان ORIGINAL و پاسخ‌های ESTABLISHED/RELATED همان تونل accept شوند؛ هیچ policy پیش‌فرض firewall تغییر نکند. باید hook precedence و تداخل با firewall مدیر دیگر تشخیص داده شود.
7. Rule ordering قطعی: **specific-port mappings نخست، all-except پس از آن**. هر نوع همپوشانی که مقصد مبهم یا غیرقابل‌پیش‌بینی ایجاد کند باید از پیش **رد** شود، نه اینکه با ترتیب تصادفی حل گردد.
8. پروتکل‌های غیر از TCP/UDP در all-except نه تغییر داده شوند و نه block.
9. رویدادهای conntrack فعال پس از حذف یا تغییر DNAT ممکن است با mapping قبلی تا پایان session ادامه پیدا کنند؛ UI صریحاً اعلام کند؛ هرگونه حذف conntrack به‌صورت دسته‌جمعی ممنوع و پاکسازی selective فقط در فاز بعد با تأیید صریح.

### 6.3 شناسایی تعارض‌ها — Fail Closed

هر کدام از موارد زیر قبل از apply باید خطای `E_CONFLICT` بدهد:

- IP/Interface ورودی نامعتبر یا پورت listen که متعلق به سرویس local، تونل دیگری یا NAT غیر V2 است.
- DNAT دیگری که با `(interface, listen_ip, protocol, listen_port)` هم‌پوشانی یا حالت all-except ناسازگار دارد؛ از جمله قوانین قدیمی DDS-Tunnel.
- UFW، firewalld یا manager شبکه دیگری که کنترل ruleset دارد و ترتیب ruleها را نمی‌توان با تست قابل‌تکرار تضمین کرد؛ تا زمان ایجاد adapter تست‌شده، هیچ override عمومی وجود ندارد.
- تونل all-except که پورت SSH فعال و پورت `22` را در فهرست exclude ندارد؛ پورت‌های مدیریتی کشف‌شده و listenerهای فعال باید یا مستثنا باشند یا عملیات رد شود.
- target که route آن به خود سرور، interface loopback یا مسیر حلقه‌ای برمی‌گردد.
- نگاشت duplicate، زنجیره V2 با مالک ناشناس، backend تغییرکرده یا چند process هم‌زمان تغییر قوانین.

حداکثرهای MVP: **100 تونل فعال، 512 نگاشت پروتکل/پورت فعال روی سرور، 1024 پورت استثنا برای هر all-except**. عبور از حد باید با پیام مشخص رد شود؛ این حدود باید به‌عنوان constant و تست واحد ثبت شوند.

### 6.4 حفظ اتصال SSH

- پورت SSH فعال با `ss -ltnp` و در صورت امکان اطلاعات `sshd` کشف شود؛ 22 به‌عنوان fallback محافظت شود.
- حفاظت فقط SSH نیست: پورت‌های پنل مدیریتی و listenerهای حیاتی کشف‌شده باید در preflight ظاهر شوند؛ در all-except لازم است مستثنا باشند.
- هیچ تغییری در policyهای INPUT/OUTPUT، default route یا listen port سرویس‌های سیستم انجام نشود.
- در اعمال پرخطر، rollback محافظ زمان‌دار: تغییر pending با ID ایجاد شود، یک سرویس یا timer یکبارمصرف systemd پس از **120 ثانیه** در صورت عدم `portmanager2 confirm <change-id>` وضعیت قبلی V2 را restore کند. `confirm` فقط وقتی موفق شود که change-id دقیقاً با تراکنش pending منطبق است و health-check بعد از اعمال موفق بوده است؛ سپس timer همان تراکنش لغو و pending commit شود. reboot حین پنجره pending باید با restore به وضعیت قبلیِ تأییدشده منتهی شود. این fallback فقط ruleهای مالکیتی V2 را تغییر می‌دهد.
- mode تعاملی باید تأیید را آشکار کند؛ `--yes` تایید امنیتی را غیرفعال نمی‌کند. این مکانیزم به‌صورت خودکار روی عملیات all-except و تغییر interface/listen-ip فعال شود.

## 7. تراکنش اعمال و rollback

**ترتیب اجباری اجرای تغییر (هر tunnel create/update/delete/enable/disable):**

1. `flock` غیرمسدودکننده روی `/run/lock/portmanager2.lock`؛ عدم موفقیت => `E_LOCKED`.
2. خواندن config+generation و تشخیص backend/وضعیت شبکه.
3. validate ورودی، تعارض TCP/UDP، SSH، listenerها، V1 و NAT خارجی؛ بدون mutation.
4. ساخت manifest و پیش‌نمایش diff دقیق own chains/hooks.
5. ذخیره فایل `pending transaction` و backup config و owned-rules، با checksum و `fsync`.
6. آزمایش نحو ورودی `iptables-restore --test` روی فایل مرحله‌ای `--noflush`، با محدودکردن تغییرات به own chains (نحوه استفاده از ابزار باید با backend مربوطه تست واقعی شود).
7. اعمال staged و idempotent به‌ترتیبی که اتصال موجود حفظ شود؛ از `iptables-restore --noflush` و commitهای جدول به جدول یا دستورات محدود مالکیتی استفاده شود. **اتمیک بودن تمام جدول‌ها با یک commit فرض نشود**.
8. در failure، از previous-owned-manifest، **فقط** زنجیره‌ها و hookهای قبلی V2 بازیابی شوند؛ داده‌ها و قوانین V1 دست نخورند.
9. فقط پس از apply موفق، `config.json` و generation جدید اتمیک persist شود؛ `applied_generation` ثبت شود. برای عملیات محافظت‌شده، حالت pending تا تأیید کاربر باقی بماند.
10. در rollback ناموفق، `E_ROLLBACK`, log سطح CRITICAL، راهنمای دستی restore و حفظ snapshot صادر شود؛ سیستم بدون گزارش موفقیت کاذب خاتمه یابد.

**Idempotency:** دو بار اجرای `portmanager2 restore` یا `tunnel apply` با همان generation باید همان تعداد دقیق hook و rule تولید کند؛ counters ممکن است تغییر کنند اما rule duplicate نباید اضافه شود.

**سازگاری با iptables-persistent:** V2 از فایل rules.v4 برای persistence استفاده نمی‌کند. `portmanager2-restore.service` باید پس از `network-online.target` و در صورت وجود پس از `netfilter-persistent.service` اجرا شود. اگر service خارجی بعداً ruleset را تغییر داد، `doctor` drift را گزارش کند؛ V2 بدون احراز مالکیت هیچ چیزی از سایر سرویس‌ها پاک نکند.

**IP forwarding:** اگر `net.ipv4.ip_forward=0` باشد، V2 با ایجاد فایل اختصاصی `/etc/sysctl.d/91-portmanager2-forward.conf` آن را فعال کند، پس از ثبت snapshot وضعیت. V2 نباید `/etc/sysctl.d/30-ip_forward.conf` مربوط به تونل قدیمی یا فایل sysctl دیگری را بازنویسی کند. حذف V2 **نباید کورکورانه ip_forward را 0 کند**، چون ممکن است سرویس دیگر به آن نیاز داشته باشد؛ فایل خود را حذف و در صورت نیاز فقط هشدار مدیریتی صادر کند.

## 8. مرز مشترک V1 و V2: مانیتورینگ و `tc`

### 8.1 وضعیت واقعی V1

در نسخه مرجع، V1:

- به‌صورت پیش‌فرض `DIR=/etc/portmanager` و `DATA=/var/lib/portmanager` دارد.
- شمارش را با chain اختصاصی `PORTMANAGER_ACCT` در جدول `mangle` و شرایط conntrack انجام می‌دهد.
- با اجرای محدودکننده `tc`، **root qdisc و ingress qdisc اینترفیس منتخب را پاک و دوباره می‌سازد**.
- برای sample و restore limit از cron استفاده می‌کند.

**نتیجه طراحی:** «جدا بودن باینری‌ها» به‌معنای همزیستی بی‌خطر محدودکننده‌های شبکه نیست. V2 نباید مدیریت انحصاری `tc` را بی‌دلیل در حضور V1 ادعا کند.

### 8.2 رفتار اجباری در حالت نصب همزمان

- V2 اجازه دارد تونل‌های خودش را بسازد و گزارش‌های مستقل خود را از زنجیره `PM2_ACCOUNT` بگیرد، بدون پاکسازی یا تغییر `PORTMANAGER_ACCT`.
- V2 مجاز نیست برای سنجش ترافیک، زنجیره‌های V1 را reset یا flush کند.
- اگر `/usr/local/bin/portmanager` و cron آن وجود دارد یا روی interface qdisc غیر V2 دیده شد، `limits set` در V2 روی همان interface باید **E_CONFLICT** بدهد؛ فقط monitor + tunnel کار کند.
- V2 نباید qdisc پیش‌فرض/متعلق به V1 را با `tc qdisc del dev ... root` یا `ingress` حذف کند.
- در **2.0.0 `limits set/remove` هیچ‌گاه `tc` را mutate نکنند**: وجود V1 یا qdisc خارجی ⇒ `E_CONFLICT`؛ نبود تعارض ⇒ `E_UNSUPPORTED` با متن «در 2.1.x عرضه می‌شود».
- در **2.1.x** فعال‌سازی کنترل سرعت V2 فقط در صورت اثبات مالکیت qdisc اختصاصی V2 و عدم حضور مالک رقیب مجاز است؛ در نبود مالکیت **نمایش وضعیت unsupported/conflict**، نه اعمال ناقص.
- اگر V1 پس از فعال‌سازی limiter نسخه 2.1.x تنظیم `tc` را بازنویسی کرد، `doctor` باید drift را تشخیص دهد، limiter V2 را غیرفعال/نامعتبر علامت بزند و هیچ repair خودکار تهاجمی نکند.
- حتی پس از 2.1، محدودسازی سرعت همزمان V1 و V2 روی یک interface تا ساخت adapter/مهاجرت تاییدشده پشتیبانی نمی‌شود.

### 8.3 موتور حسابداری تونل

- hook `PM2_ACCOUNT` در `mangle/FORWARD`؛ انتخاب بر اساس conntrack ORIGINAL IP/port/protocol و `ctdir ORIGINAL` برای upload، `ctdir REPLY` برای download.
- هر بسته فقط **یک بار** در آمار تونل V2 شمرده شود. ruleها به شکلی تولید شوند که یک packet در دو entry از یک تونل یا دو تونل V2 duplicate نشود.
- آمار IPv4 NAT را بعد از rewrite نیز با tuple ORIGINAL تشخیص دهد؛ استفاده صرف از destination port خروجی برای تعیین تونل **ممنوع**.
- شمارش شامل bytes روی hook است، نه الزاماً application payload؛ این تفاوت در UI توضیح داده شود.
- sampler هر 60 ثانیه counter snapshot می‌گیرد؛ dashboard live هر 1 ثانیه از delta counters سرعت را محاسبه می‌کند. نرخ در اولین نمونه `N/A` تا دریافت نمونه دوم باشد.
- زمان‌بندی `sample` صرفاً `systemd timer` اختصاصی V2؛ هیچ سطری در root crontab V1 اضافه/حذف نشود.

## 9. TUI: صفحه‌ها و رفتار دقیق

```text
PORT MANAGER 2 | Tunnel Edition | v2.x
[01] Network Dashboard
[02] Tunnel Management
[03] Port Mapping
[04] Live Traffic Monitor
[05] Bandwidth Limits
[06] Traffic Reports
[07] Firewall & Diagnostics
[08] Backup & Restore
[09] Settings / About
[00] Exit
```

- صفحه **Tunnel Management** زیرمنوی List / Add / Edit / Enable / Disable / Delete / Details / Apply داشته باشد.
- Add/Edit با wizard ثابت: Name → Interface → Listen IPv4 → Mode → Protocol → Mapping/Exclude → Target IPv4 → Summary/Dry-run → Confirm.
- صفحه list ستون‌های `ID(short)`, `Name`, `Mode`, `Protocol`, `Listen`, `Target`, `State`, `Up`, `Down` را نشان دهد؛ terminal باریک جدول به‌صورت چندخطی تطبیق یابد.
- هر تغییر پیش از commit، diff و پیام خطر را نشان دهد. گرفتن تأیید با Enter پیش‌فرض **No** باشد.
- رنگ فقط کمک بصری است؛ status متنی الزامی تا روی terminal فاقد ANSI نیز قابل استفاده باشد.
- کلید `0`/`Esc` در هر زیرمنو به منوی قبلی بازگردد؛ `Ctrl+C` بدون نوشتن نیمه‌تمام، با exit 130 خارج شود.
- هر خطای validation باید فیلد معیوب، مقدار، قاعده معتبر و راه اصلاح را نشان دهد؛ هیچ `Traceback` خام در حالت عادی به کاربر نشان داده نشود.

## 10. نصب، به‌روزرسانی، حذف و بازیابی

### 10.1 نصب V2

1. بررسی root، OS، معماری، Python، iptables backend و سلامت DNS/HTTPS؛ نمایش فهرست تغییرات قبل از اعمال.
2. دانلود از release/tag مشخص و قابل ردیابی؛ اعتبارسنجی checksum همه فایل‌ها با manifest قابل‌اعتماد وابسته به release و ثبت commit SHA. دانلود مستقیم `master` بدون ثبت provenance نسخه منتشرشده کافی نیست.
3. ایجاد staging در `/opt/portmanager2/releases/<version>.staging`؛ lint/compile check Python و verify manifest.
4. بررسی تعارض نام `portmanager2` و مسیرهای اختصاصی؛ **بدون لمس V1**.
5. جابه‌جایی staging به release کامل و سپس **atomic swap** symlink `current`، با ذخیره اشاره‌گر نسخه قبلی؛ پس از این مرحله launcher نسخه جدید را اجرا می‌کند.
6. نصب systemd units با filenames اختصاصی؛ `daemon-reload`؛ فعالسازی sampler timer و restore service مطابق حالت نصب.
7. اجرای `portmanager2 doctor` در حالت read-only و smoke test `--version`. اگر هرکدام شکست خورد، **symlink را به نسخه قبلی برگردان، units تازه را حذف/restore کن و داده‌های V1 را دست نزن**. به‌جز عملیات صریح فعالسازی forwarding، هیچ تغییر NAT در نصب خالی اعمال نشود.
8. گزارش ورژن، مسیرها، وضعیت و دستور اجرا `portmanager2`.

### 10.2 Upgrade/Downgrade

- Semantic Versioning: `2.MAJOR.MINOR.PATCH` ممنوع؛ نسخه به‌صورت `MAJOR.MINOR.PATCH` از `2.0.0` آغاز شود.
- `portmanager2 --version` با VERSION تطابق دقیق داشته باشد.
- schema migration فقط forward با backup خودکار؛ downgrade در صورت عدم پشتیبانی schema با خطا و عدم mutation متوقف شود.
- `CHANGELOG.md` شامل Added/Changed/Fixed/Security/Breaking و ارجاع bug ID باشد.
- rollback انتشار: symlink به release قبلی، restore config سازگار، و apply owned-rules از manifest قبلی؛ بدون بازگرداندن snapshot جهانی iptables.

### 10.3 Uninstall

- `uninstall` باید ابتدا وضعیت اتصالات و تغییر مسیر ترافیک را هشدار دهد، dry-run فهرست دقیق فایل‌ها/chainهای مربوط را نمایش دهد، تایید صریح بگیرد، سرویس‌های خودش را متوقف و غیرفعال کند، hooks خودش را حذف کند و سپس chains خودش را پاک کند.
- اگر chain مربوطه توسط برنامه غیر V2 تغییر یافته یا reference ناشناس دارد، حذف باید fail closed شده و راهنمای رفع تعارض بدهد.
- هر فایلی خارج از prefixهای V2 (از جمله `/etc/iptables/rules.v4`) دست‌نخورده بماند.
- `--purge` داده‌های config, DB, backup و log مخصوص V2 را فقط پس از تأیید اضافی حذف کند.
- exit در failure نباید موفقیت نصب/حذف نمایش دهد.

## 11. خطاها، دیباگ، تست‌ها و جلوگیری از رگرسیون

### 11.1 Logging & observability

- پیام‌ها با timestamp ISO-8601 UTC، level، component، event code، tunnel ID (در صورت وجود)، generation، request_id.
- سطح‌های INFO/WARN/ERROR/CRITICAL. اطلاعات حساس، IP کاربران و payload بسته‌ها **به‌طور پیش‌فرض لاگ نشوند**.
- `portmanager2 doctor --json` دست‌کم این‌ها را گزارش کند: root/deps, OS, iptables backend, V1 installed, V1 cron presence, qdisc ownership, chain ownership, rules drift, ip_forward, systemd units, config schema, DB health, interface route, active tunnels.
- `portmanager2 backup create` خروجی config + owned rule manifests + schema-version + hashes بسازد؛ restore وضعیت دیگر برنامه‌ها ممنوع است.

### 11.2 رده‌بندی باگ

| سطح | مصداق | اقدام اجباری |
|---|---|---|
| P0 | قطع SSH، حذف firewall غیرخودی، قطع پایدار سرویس V1، فساد گسترده ruleset | توقف انتشار، rollback فوری نسخه آزمایشی، نگارش postmortem، تست regression اجباری |
| P1 | عدم عبور TCP/UDP، SNAT اشتباه، گزارش متناقض، عدم recovery پس از reboot | رفع پیش از release؛ تست netns + VM |
| P2 | خطای UI، ناسازگاری چند پورت، کندی مانیتورینگ، مشکل JSON API | bugfix با testcase و patch |
| P3 | نمایش، متن، مستندات، polish | طبق backlog |

### 11.3 پروتکل استاندارد رفع هر باگ

1. Issue با `PM2-BUG-NNN`، نسخه، OS، backend iptables، وضعیت V1، وضعیت qdisc، مراحل بازتولید، expected/actual و log بی‌اطلاعات حساس بساز.
2. قبل از fix، یک **تست شکست‌خورنده قابل بازتولید** بنویس (`tests/regression/test_bug_nnn.py`). اگر امکان automated test نیست، manual reproducible script مستند شود.
3. Root Cause Analysis شامل توضیح علت فنی، blast radius، علت عبور از تست قبلی و اثر بر نسخه قبل ثبت کن.
4. کوچک‌ترین fix بدون تغییر رفتار تعریف‌شده سند اجرا شود؛ برای تغییر API یا scope باید spec version بالا رود.
5. Unit + integration + coexistence test + upgrade/downgrade + regression مربوط اجرا شوند؛ نتیجه در PR ثبت شود.
6. در باگ P0/P1، تست دستیِ حفظ SSH/V1 و reboot روی VM انجام و evidence ذخیره شود.
7. Review مستقل: بررسی عدم وجود `iptables -F/-X` عمومی، `tc qdisc del` بی‌مالکیت، تغییر V1، `shell=True`, رفتار fail-open.
8. Patch با SemVer و CHANGELOG منتشر شود؛ در صورت P0/P1 اطلاعیه downgrade/rollback نوشته شود.
9. باگ تنها وقتی Closed شود که regression جدید در CI سبز، reproduction قبلی حل و معیار پذیرش مرتبط برقرار شده باشد.

### 11.4 استاندارد کیفیت

- Python: `ruff` یا `flake8` (یکی انتخاب و قفل نسخه شود)، `mypy` در مرزهای firewall/config، `python -m compileall`, `pytest`.
- Bash: `bash -n`, `shellcheck` برای تمامی `.sh` جدید، `shfmt` در صورت موجود بودن.
- هر اجرای subprocess دارای timeout، capture exit code، stderr و retry فقط برای خطاهای transient/lock تعریف‌شده؛ retry بدون سقف ممنوع.
- تست unit بدون root و بدون دسترسی شبکه به کمک mock command runner.
- تست integration دارای محیط جدا از host production؛ تست حقیقی `iptables` فقط VM یا netns اختصاصی با capability مناسب.
- کد باید idempotent، قابل audit، دارای docstring برای مراحل خطرناک و فاقد اجرای مستقیم shell input باشد.

## 12. ماتریس تست پذیرش (Acceptance Tests)

هر آزمون `PM2-AT-###` دارد و **بدون نتیجه Pass قابل انتشار نیست**. قبل/بعد عملیات، fingerprint فایل‌های V1 (`sha256` فایل‌های اجرایی و کانفیگ؛ snapshot DB با روش سازگار)، root crontab، V1 owned chain و qdisc ثبت شود؛ تغییر طبیعی counters و timestampها در مقایسه لحاظ گردد.

| ID | شرایط / اقدام | انتظار دقیق |
|---|---|---|
| AT-001 | نصب V1 با URL اصلی در VM خالی | اجرای `portmanager` و فایل‌های V1 مطابق baseline |
| AT-002 | نصب V1 با URL جدید | همان فایل اجرایی و داده‌های قابل قیاس AT-001؛ `portmanager2` اضافه نشود |
| AT-003 | نصب V2 روی VM خالی | `portmanager2 --version` موفق؛ `portmanager` ایجاد نشود |
| AT-004 | نصب V2 روی سرور با V1 فعال | فایل‌ها، cron، config، قوانین V1 هیچ mutation غیرمجاز نداشته باشند |
| AT-005 | نصب دوباره V2 | هیچ hook/rule/timer تکراری ساخته نشود؛ داده آمار باقی بماند |
| AT-006 | حذف V2 در کنار V1 | V1 اجرا شود؛ chain/cron/data آن محفوظ باشد |
| AT-007 | حذف V2 با `--purge` | فقط مسیرهای V2 پاک شوند؛ V1 همچنان سالم |
| AT-008 | Tunnel TCP پورت 443→8443 | ارتباط TCP و destination port دقیق درست؛ سایر پورت‌ها دست‌نخورده |
| AT-009 | Tunnel UDP 2053→2053 | ارتباط و بسته پاسخ UDP درست |
| AT-010 | TCP+UDP دو پورت چندگانه | همه mappingها کار کنند؛ بدون duplicate |
| AT-011 | چند تونل با listen-ip/port متفاوت | مستقل و هم‌زمان کار کنند |
| AT-012 | ساخت mapping overlap با V2 | `E_CONFLICT` و صفر mutation |
| AT-013 | overlap با DNAT غیروابسته/V1 | `E_CONFLICT` و عدم جابه‌جایی rule قبلی |
| AT-014 | all-except بدون exclude پورت SSH | fail closed، اتصال SSH پابرجا |
| AT-015 | all-except با exclusions صحیح | پورت‌های مستثنا local؛ سایر TCP/UDP به مقصد |
| AT-016 | تکرار `restore` سه مرتبه | شمار قواعد و hookها ثابت |
| AT-017 | reboot در حضور V1+V2 | هر دو اجرا؛ NAT V2 و cron V1 سالم؛ شبکه قابل دسترس |
| AT-018 | قتل عمدی عملیات وسط apply | rollback owned-rules و config، بدون آسیب به V1 |
| AT-019 | قطع process در rollback | `E_ROLLBACK`/Recovery alert و backup قابل استفاده |
| AT-020 | تغییر backend iptables پس از نصب | `E_CONFLICT` و عدم mutation |
| AT-021 | UFW/firewalld فعال بدون adapter | عملیات اعمال با پیام واضح رد شود |
| AT-022 | تمام فرمان‌های تغییردهنده که `--dry-run` دارند | zero mutation فایل‌ها، chainها، timer و DB |
| AT-023 | شمارش TCP/UDP با DNAT و port rewrite | Up/Down مطابق byte counters با تحمل تعریف‌شده؛ بدون double count |
| AT-024 | counters reset/reboot | دلتا منفی و پرش غیرواقعی ایجاد نشود؛ history باقی بماند |
| AT-025 | گزارش 1h/24h/7d و JSON | schema و window coverage ثابت؛ اعداد با نمونه‌ها سازگار |
| AT-026 | وجود V1 یا qdisc غیر V2؛ limits set | `E_CONFLICT`، qdisc و limit V1 تغییر نکنند |
| AT-027 | V2 تنها و بدون V1؛ `limits set` | در 2.0.0 حتماً `E_UNSUPPORTED` و **صفر mutation در tc**؛ تست shaping فقط در 2.1.x |
| AT-028 | invalid IP، port=0/65536، malformed mapping | `E_VALIDATION` و صفر mutation |
| AT-029 | دو apply همزمان | فقط یکی تغییر اعمال کند؛ دیگری `E_LOCKED` |
| AT-030 | disk-full یا config JSON نامعتبر | config قبلی سالم؛ پیام خطا و recovery path |
| AT-031 | توقف اتصال مدیریتی در change محافظت‌شده | پس از 120 ثانیه بدون confirm، rollback فقط تغییرات V2 |
| AT-032 | V1 نصب مجدد بعد از V2 | V2 drift qdisc را شناسایی کند؛ بدون overwrite تهاجمی |
| AT-033 | حذف یک تونل بین چند تونل | فقط rule تونل هدف حذف شود؛ بقیه کار کنند |
| AT-034 | یک مقصد unreachable | apply با route معتبر طبق سیاست مشخص، خطای runtime قابل گزارش؛ سایر تونل‌ها سالم |
| AT-035 | عملکرد در terminal غیر ANSI / اندازه کوچک | امکان استفاده و بازگشت امن از منو |
| AT-036 | `portmanager2 --json` در تمام status/list/doctor | JSON معتبر، بدون banner و بدون اطلاعات حساس |
| AT-037 | 16 و 1024 پورت exclude | همه استثناها صحیح؛ هیچ اتکا به محدودیت 15تایی multiport |
| AT-038 | تلاش cleanup در وجود rule با مالک ناشناس | توقف حذف و گزارش تعارض؛ rule غیروابسته پاک نشود |
| AT-039 | فعال بودن ip_forward توسط V1؛ حذف V2 | ip_forward به 0 برنگردد |
| AT-040 | تست قبل/بعد روی network namespace و VM | هیچ flush / policy-change عمومی انجام نشود |

### 12.1 محیط شبکه تست قطعی

- سه network namespace یا سه VM سبک: `client`, `relay`, `target` با veth و routeهای آشکار. relay دارای IP ورودی و IP خروجی، target دارای سرویس TCP و UDP echo؛ ارتباط از client به relay به target بررسی شود.
- تست اتصالات با `nc` یا برنامه TCP/UDP echo ساده؛ برای ترافیک و محدودکننده از `iperf3` در VM اختیاری استفاده شود.
- حداقل 2 backend `iptables-nft` و `iptables-legacy` در صورت پشتیبانی OS، دو خانواده OS Ubuntu و Debian؛ نتایج هر ترکیب مجزا ثبت شود.
- integration test علاوه بر ping/port-connect باید بررسی کند **سرور هدف IP source مورد انتظار** (SNAT/MASQUERADE) را دریافت کرده و پاسخ از route درست برگردد.
- تست‌های مخرب در production ممنوع؛ استفاده از snapshot قبل از تست و console/recovery access در VM الزامی.

### 12.2 CI و Release gates

**Gate A — Static:** bash lint, Python lint/type/compile, JSON schema, security scan، عدم تغییر مسیرهای ممنوع V1.  
**Gate B — Unit:** schema/validation/rule generator/rollback/CLI همه سبز.  
**Gate C — Network Integration:** TCP, UDP, multimap, all-except, NAT, conntrack, SNAT, anti-overlap، drift.  
**Gate D — Coexistence:** AT-001..007, AT-017, AT-026, AT-032, AT-039 و fingerprint V1.  
**Gate E — Failure Injection:** apply partial failure، disk-full، lock contention، reboot، missing dependency، timer rollback.  
**Gate F — Release:** نسخه، changelog، نصب clean و update، uninstall، مستندات، مجوزها و تأیید دستی امنیت SSH.

انتشار V2 روی `master` فقط زمانی مجاز است که تمام Gateها pass و evidence در PR موجود باشد.

## 13. نقشه راه مرحله‌به‌مرحله و تحویل هر مرحله

### فاز 0 — Freeze & Audit

**کارها:** تثبیت commit مبنا، استخراج سورس V1 از Base64 صرفاً برای بررسی، شناسایی `PORTMANAGER_ACCT` و مسیرهای cron/tc، استخراج رفتار DNAT قدیمی، ثبت hash فایل‌ها و risk register.  
**تحویل:** `ARCHITECTURE.md`, `FIREWALL-OWNERSHIP.md`, V1 fingerprint manifest و تست عدم‌تغییر.  
**قبولی:** یک PR آزمایشی ثابت کند هیچ فایلی زیر `portmanager-dashboard/` تغییر نکرده است.

### فاز 1 — Version Routing & V2 Bootstrap

**کارها:** افزودن `portmanager-v1/install.sh` alias، ساخت skeleton V2، installer امن، pathهای مجزا، CLI help/version/status، systemd install/uninstall بدون قوانین NAT.  
**تحویل:** URLهای سه‌گانه، `portmanager` و `portmanager2`، install/uninstall idempotent.  
**قبولی:** AT-001..007, AT-022 روی نصب خالی و V1 فعال.

### فاز 2 — Core Firewall / Tunnel

**کارها:** schema و parser، own chains، IPv4 port-mapping، TCP/UDP، conflict checker، rollback، عملیات CRUD، persisting روی reboot.  
**تحویل:** `tunnel create/list/update/enable/disable/delete/apply`, doctor پایه.  
**قبولی:** AT-008..013, AT-016..022, AT-028..030, AT-033, AT-038..040.

### فاز 3 — All-Except & SSH Guard

**کارها:** حفاظت پورت‌های مدیریتی، exclusions مستقل، all-except، rollback با تأیید 120s، پیاده‌سازی fail-closed روی فایروال‌های خارجی.  
**تحویل:** حالت all-except کاملاً قابل تست در VM.  
**قبولی:** AT-014, AT-015, AT-031, AT-037 + تست دستی عدم قطع SSH.

### فاز 4 — Accounting / Dashboard / Report

**کارها:** شمارش per-tunnel مبتنی بر ORIGINAL conntrack، counter reset handling، SQLite، systemd sampler، پنل live، گزارش‌های 1h/24h/7d.  
**تحویل:** داشبورد قابل استفاده و JSON گزارش.  
**قبولی:** AT-023..025, AT-035..036؛ بدون دخالت در `PORTMANAGER_ACCT`.

### فاز 5 — `tc` Conflict Safety و مرزبندی Limit

**کارها:** qdisc ownership detector، fail closed در حضور V1/external tc، ثبت وضعیت limiter؛ در 2.0 دستورات تغییر محدودیت طبق قرارداد **حتماً فاقد mutation** باشند (`E_CONFLICT` در تعارض، وگرنه `E_UNSUPPORTED`).  
**تحویل:** API باثبات و پیام تعارض/عدم‌پشتیبانی واضح؛ **هیچ تغییر qdisc در 2.0.0**.  
**قبولی:** AT-026, AT-027, AT-032؛ آزمون کنترل سرعت مستقل در صورت ارائه ادعای پشتیبانی.

### فاز 6 — Hardening & Release 2.0.0

**کارها:** اجرای تمام ماتریس روی Ubuntu/Debian، تست Reboot، Failure Injection، رفع باگ‌ها، README فارسی/انگلیسی، CLI reference، CHANGELOG، release tag و rollback guide.  
**تحویل:** انتشار نسخه قابل نصب V2 در `master`، حفظ نصب قبلی و V1 alias.  
**قبولی:** Gate A..F سبز و **صفر P0/P1 باز**.

### فاز 7 — توسعه 2.1.x (بعد از پایدارشدن 2.0)

**کارها:** shaping دقیق per-tunnel و per-direction تحت مالکیت انحصاری V2، quota و alert، export، healthcheck، بهبود داشبورد.  
**قبولی:** throughput test با تعریف تحمل خطا، بدون overwrite qdisc V1، SemVer و migration versioned.

## 14. ریسک‌های شناخته‌شده و راه رفع قطعی

| ریسک | عامل | راه‌حل معماری |
|---|---|---|
| قطع سرور با Flush | DDS-Tunnel قدیمی از flush سراسری استفاده می‌کند | کپی نکردن این رفتار؛ chain مالکیتی + transactional rollback |
| خرابی V1 limiter | V1 مالکیت انحصاری `tc` را فرض می‌کند | fail closed و no-op limiter V2 در حضور V1/external qdisc |
| تداخل NAT دو برنامه | Port overlap و تغییر پورت مقصد | preflight original tuple + reject overlap |
| از دست رفتن SSH | all-except پورت مدیریت را می‌بلعد | mandatory excludes + listener inspection + timed rollback |
| چند بار اضافه‌شدن rule | اجرا/نصب دوباره | generation، owned manifest، idempotent reconcile |
| از بین رفتن آمار در reboot | counter kernel صفر می‌شود | counter_epoch + persistent SQLite |
| ناسازگاری nft/legacy | ابزارهای iptables frontend متفاوت | detect/pin backend + تست مجزا + fail closed |
| پاک‌شدن قوانین V2 توسط netfilter-persistent | ترتیب systemd | `After=netfilter-persistent.service`, boot restore و doctor drift |
| تخریب config هنگام قطع برق | نوشتن ناقص فایل | temp + fsync + atomic rename + checksum backup |
| دستورات مخرب root | shell injection یا command concat | subprocess argv و validation strict |
| نبود route دوطرفه | SNAT/route اشتباه | `ip route get`, per-flow SNAT، تست reply در namespace |
| مجوز ناقص upstream | ترکیب و بازنشر کد تونل با GPL-3.0 | بررسی license/copyright، نگهداری اعلان‌ها و رعایت تعهدات مشتق‌شدن در انتشار |

## 15. Definition of Done نهایی

پروژه فقط وقتی «تحویل‌شده» است که تمامی موارد زیر واقعاً برقرار باشند:

- [ ] دستور **اصلی قدیمی** دقیقاً V1 را نصب می‌کند و باینری `portmanager` بدون تغییر باقی می‌ماند.
- [ ] دستور جدید اختصاصی **V1** همان محصول قدیمی را نصب می‌کند.
- [ ] دستور اختصاصی **V2** محصول جدید را مستقل نصب می‌کند و `portmanager2` را اجرا می‌کند.
- [ ] Source, runtime, config, database, cron و rules V1 توسط V2 تغییر نمی‌کنند.
- [ ] V1 و V2 کنار هم قابل نصب و اجرا هستند؛ محدودیت هم‌زمانی shaping مستند و fail closed است.
- [ ] حالت TCP/UDP، port mapping و all-except در تست شبکه با return traffic سالم کار می‌کنند.
- [ ] هیچ rule غیر V2 با `flush`, `delete`, `restore`, `uninstall` یا `rollback` تغییر نمی‌کند.
- [ ] حفاظت SSH، preflight، سیستم backup، timer rollback و restore بعد از reboot تست شده‌اند.
- [ ] شمارش per-tunnel مبتنی بر conntrack با تغییر پورت مقصد نیز درست و بدون double count است.
- [ ] `--dry-run`, `--json`, error codes و متن CLI طبق قرارداد رعایت شده‌اند.
- [ ] همه تست‌های AT-001..040 و Gate A..F پاس شده‌اند.
- [ ] مستندات نصب، uninstall، debugging، known limitations، مجوزها و changelog منتشر شده‌اند.
- [ ] صفر P0/P1 باز و تست fingerprint V1 سبز است.

## 16. دستور مستقیم برای هوش مصنوعی مجری

> **نقش شما:** توسعه‌دهنده ارشد Linux networking/Python و مسئول تحویل کد production-grade در ریپازیتوری `smorad3363/assistant-vps`. فایل حاضر «مرجع الزام‌آور» است. قبل از کدنویسی، ساختار و SHA مبنای دو پروژه را بازبینی کن؛ سپس فازهای 0 تا 6 را دقیقاً به ترتیب اجرا کن. هیچ تغییر رفتاری در `portmanager-dashboard/` نده؛ URL نصب قدیمی باید همیشه V1 نصب کند. یک `portmanager-v1` alias و `portmanager-v2` مستقل بساز. همه فایل‌ها، فرمان‌ها، state schema، خطاها، NAT rules، systemd و آزمون‌ها را طبق سند توسعه بده. هر مرحله باید PR/commit کوچک، گزارش فایل‌های تغییر یافته، تست‌های اجرایی و ریسک‌های باقی‌مانده داشته باشد. در صورت ناتوانی از اجرای تست privileged، وضعیت آن را صادقانه «NOT TESTED» بنویس؛ هرگز فرض نکن درست است. هیچ رفتار خطرناک global iptables flush یا حذف qdisc غیرخودی پیاده نکن. اجرای تست مخرب فقط روی VM/netns مجاز است. کد منتشرنشده را «نصب آماده» اعلام نکن. برای خروجی، کد کامل فایل‌ها + تست + README + CHANGELOG + گزارش پوشش Acceptance Tests را تحویل بده. اگر قابلیتی در 2.0.0 طبق سند خارج از محدوده است، خطای شفاف unsupported بده، نه پیاده‌سازی نصفه‌نیمه. اگر قرارداد مبهم شد، کم‌خطرترین رفتار fail-closed را انتخاب کن، تصمیم را به‌صورت ADR در docs ثبت کن و بی‌سروصدا رفتار جدید ایجاد نکن.

---

### پیوست A — چک‌لیست Code Review امنیتی

- [ ] هیچ `iptables -t nat -F`, `iptables -F`, `iptables -P ACCEPT`, `iptables-save > /etc/iptables/rules.v4` در V2 وجود ندارد.
- [ ] هیچ `tc qdisc del` بر interface غیرخودی اجرا نمی‌شود.
- [ ] هیچ کدی `/usr/local/bin/portmanager` یا `/etc/portmanager` یا `/var/lib/portmanager` نمی‌نویسد.
- [ ] هر `iptables-restore` دارای `--noflush` یا معادل محدود مالکیتی است؛ global snapshot restore خودکار ممنوع.
- [ ] نام chainها و commentها مالکیت صریح V2 دارند؛ commentهای غیرخودی صرف شباهت پاک نمی‌شوند.
- [ ] هر apply قبل از mutation تعارض SSH و NAT را چک می‌کند.
- [ ] target route و local loop بررسی می‌شوند.
- [ ] اجرای مجدد install/restore باعث rule duplication نمی‌شود.
- [ ] صورت‌جلسه تست privilege-level و یک آزمون reboot واقعی موجود است.
- [ ] git diff مسیر V1 نسبت به baseline تهی است.

### پیوست B — یادداشت‌های سازگاری

- اسکریپت اصلی DDS-Tunnel دارای گزینه پاک‌کردن **همه** قوانین iptables است و برای ادغام مستقیم ناامن محسوب می‌شود؛ V2 منطق رفتار لازم را بازپیاده‌سازی می‌کند، نه command خطرناک را.
- V1 ابزار مانیتورینگ port-centric است، نه per-tunnel. V2 آمار مختص تونل را با زنجیره مستقل فراهم می‌کند. در صورت حضور V1 و V2 روی یک flow، نمایش آماری دو dashboard لزوماً جمع‌پذیر نیست و دو شیوه شمارش متفاوت‌اند.
- فعال‌سازی forward با NAT، ترافیک را رمز نمی‌کند؛ اطمینان از رمزنگاری داده‌های اپلیکیشن بر عهده پروتکل مقصد است.
- اجرای هم‌زمان versionها با حفظ فایل‌ها **به معنی ادغام بدون خطرِ shared kernel resources نیست**؛ محدودیت‌ها و fail-closed بودن جزئی از قرارداد محصول است.
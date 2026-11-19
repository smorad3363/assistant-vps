'use strict';

const rateHints = {
  'rate-up': ['سقف ارسال','حداکثر ارسال در این سطح به Mbps. فیلد خالی از سقف سطح بالاتر استفاده می‌کند.'],
  'rate-down': ['سقف دریافت','حداکثر دریافت در این سطح به Mbps. فیلد خالی از سقف سطح بالاتر استفاده می‌کند.'],
};
const mtuHint = 'بزرگ‌ترین بستهٔ IP روی رابط تونل به بایت.';
const mssHint = 'سقف دادهٔ هر قطعهٔ TCP هنگام برقراری اتصال.';
const v2FieldSchema = {
  group: {
    name: ['نام گروه','نامی که در فهرست مسیرها نمایش داده می‌شود.'],
    selection: ['انتخاب مقصد','تقسیم بار بین اولویت‌های برابر از وزن استفاده می‌کند. در حالت پشتیبان، عدد اولویت کمتر زودتر انتخاب می‌شود.'],
    enabled: ['گروه فعال','توقف گروه مسیرهای این گروه را از پذیرش اتصال تازه خارج می‌کند.'],
    ...rateHints,
  },
  listener: {
    node: ['سرور ورودی','سروری که کلاینت به آن وصل می‌شود.'],
    ip: ['IP شنونده','یکی از IPv4های فعال روی سرور ورودی.'],
    outer: ['IP بیرونی تونل','آدرسی که بستهٔ تونل از آن خارج می‌شود. اگر خالی باشد، IP شنونده استفاده می‌شود.'],
    ports: ['پورت‌ها','شماره، بازه، یا all. پورت‌های مدیریت روی هر میزبان جداگانه محافظت می‌شوند.'],
    map: ['نگاشت پورت','برای ترجمهٔ پورت، مانند 5100:5000 بنویسید. جفت‌های بعدی با کاما جدا می‌شوند.'],
    excluded: ['استثناها','شماره‌هایی که از این ورودی عبور نمی‌کنند.'],
    'port-rates': ['سقف هر پورت','شماره پورت، سقف ارسال و سقف دریافت بر حسب Mbps. نمونه 5100:20:10 است.'],
    protocol: ['پروتکل','TCP یا UDP سرویس کلاینت را مشخص می‌کند.'],
    'watch-link': ['سلامت لینک','پذیرش اتصال تازه را به نتیجهٔ سنجش مسیر داخل تونل وابسته می‌کند.'],
    'probe-protocol': ['روش سنجش','پاسخ واقعی سرویس با پروتکل انتخاب‌شده بررسی می‌شود.'],
    'probe-port': ['پورت ورودی سنجش','پنل نگاشت همین پورت را برای یافتن پورت واقعی سرویس دنبال می‌کند.'],
    'probe-request': ['متن درخواست','متن کوتاهی که سرویس برای سنجش دریافت می‌کند.'],
    'probe-response': ['پاسخ موردانتظار','متنی که سرویس باید برای تأیید سلامت برگرداند.'],
    ...rateHints,
  },
  member: {
    node: ['سرور مقصد','برای تونل، مقصد باید عامل مدیریت‌شده باشد. مقصد مستقیم می‌تواند بدون عامل باشد.'],
    method: ['روش','روش حمل بین ورودی و مقصد. پنل هنگام پیش‌نمایش تنظیم مؤثر هر دو سمت را بررسی می‌کند.'],
    service: ['IP سرویس','نشانی‌ای که واقعاً برنامهٔ مقصد روی آن پاسخ می‌دهد.'],
    outer: ['IP بیرونی مقصد','آدرس بیرونی تونل روی سرور مقصد. پیش‌فرض، IP سرویس است.'],
    mtu: ['MTU تونل',mtuHint],
    ttl: ['TTL در IPIP','حد پرش بستهٔ بیرونی. صفر یعنی مقدار بستهٔ داخلی به ارث برسد.'],
    weight: ['وزن','سهم این عضو از اتصال‌های تازه بین اعضای سالم با اولویت برابر.'],
    priority: ['اولویت','عدد کمتر زودتر انتخاب می‌شود.'],
    state: ['وضعیت مقصد','در حالت تخلیه، اتصال تازه به این مقصد نمی‌رود و نشست‌های جاری فرصت ادامه دارند.'],
    'vxlan-vni': ['شناسهٔ VNI','شناسهٔ ۲۴ بیتی شبکهٔ VXLAN که در دو سمت باید یکسان باشد.'],
    'vxlan-port': ['پورت UDP VXLAN','هر دو سمت روی این پورت حمل می‌کنند. پیش‌فرض ۴۷۸۹ است.'],
    'gretap-key': ['کلید GRETAP','کلید مشترک دو سر. در صورت خالی‌بودن، پنل یک کلید پایدار می‌سازد.'],
    'ppp-lac': ['نقش LAC','این سمت درخواست ایجاد نشست PPP را به سمت LNS می‌فرستد.'],
    'ingress-ppp-port': ['پورت L2TPv2 ورودی','یک پورت UDP آزاد روی سرور ورودی.'],
    'destination-ppp-port': ['پورت L2TPv2 مقصد','یک پورت UDP آزاد روی سرور مقصد.'],
    'ingress-ppp-credential': ['مرجع اعتبارنامه ورودی','نام فایل اعتبارنامهٔ محلی PPP روی سرور ورودی.'],
    'destination-ppp-credential': ['مرجع اعتبارنامه مقصد','نام فایل اعتبارنامهٔ محلی PPP روی سرور مقصد.'],
    'ingress-sit-ip': ['IPv6 داخلی ورودی','آدرس IPv6 ورودی همراه پیشوند بین ۶۴ تا ۱۲۶.'],
    'destination-sit-ip': ['IPv6 داخلی مقصد','آدرس IPv6 مقصد با همان پیشوند شبکهٔ ورودی.'],

    'ingress-l2tp-tunnel_id': ['شناسهٔ تونل ورودی','شناسهٔ ۳۲ بیتی تونل روی سرور ورودی.'],
    'destination-l2tp-tunnel_id': ['شناسهٔ تونل مقصد','شناسهٔ ۳۲ بیتی تونل روی سرور مقصد.'],
    'ingress-l2tp-session_id': ['شناسهٔ نشست ورودی','شناسهٔ ۳۲ بیتی نشست Ethernet روی سرور ورودی.'],
    'destination-l2tp-session_id': ['شناسهٔ نشست مقصد','شناسهٔ ۳۲ بیتی نشست Ethernet روی سرور مقصد.'],
    'ingress-l2tp-port': ['پورت UDP ورودی','پورت محلی حمل L2TPv3 در ورودی.'],
    'destination-l2tp-port': ['پورت UDP مقصد','پورت محلی حمل L2TPv3 در مقصد.'],

    'geneve-vni': ['شناسهٔ GENEVE','شناسهٔ ۲۴ بیتی که برای این لینک باید در دو سر یکسان باشد.'],
    'geneve-port': ['پورت UDP GENEVE','پورت مشترک UDP در هر دو سر. پیش‌فرض ۶۰۸۱ است.'],
    'ingress-mtu': ['MTU ورودی',mtuHint], 'destination-mtu': ['MTU مقصد',mtuHint],
    'ingress-mode': ['روش MSS ورودی',mssHint], 'destination-mode': ['روش MSS مقصد',mssHint],
    'ingress-mss': ['عدد MSS ورودی',mssHint], 'destination-mss': ['عدد MSS مقصد',mssHint],
    'ingress-wg-key': ['کلید عمومی ورودی','کلید عمومی WireGuard که روی سرور ورودی ایجاد شده است.'],
    'destination-wg-key': ['کلید عمومی مقصد','کلید عمومی WireGuard که روی سرور مقصد ایجاد شده است.'],
    'ingress-wg-port': ['پورت UDP ورودی','پورت محلی WireGuard در سمت ورودی.'],
    'destination-wg-port': ['پورت UDP مقصد','پورت محلی WireGuard در سمت مقصد.'],
    keepalive: ['Keepalive','فاصلهٔ بسته‌های نگهدارنده از ورودی به مقصد به ثانیه. صفر آن را خاموش می‌کند.'],
    ...rateHints,
  },
  benchmark: {
    first_node: ['سرور A','سنجش رفت از این سرور شروع می‌شود.'], second_node: ['سرور B','سنجش برگشت از این سرور شروع می‌شود.'],
    first: ['آدرس بیرونی A','آدرس فعال روی سرور A برای حمل آزمایش.'], second: ['آدرس بیرونی B','آدرس فعال روی سرور B برای حمل آزمایش.'],
    duration_s: ['مدت هر روش','مجموع زمان انتقال رفت و برگشت یک روش به ثانیه. آماده‌سازی جداگانه است.'],
    gre: ['GRE','اجرای یک آزمایش با رابط GRE موقت.'], ipip: ['IPIP','اجرای آزمایش با حمل مستقیم IPv4 روی IPv4.'],
    gre_time: ['مدت GRE','برای این روش می‌توان مدت اصلی را تغییر داد.'], ipip_time: ['مدت IPIP','برای این روش می‌توان مدت اصلی را تغییر داد.'],
    sit: ['SIT','انتقال دادهٔ IPv6 داخل رابط SIT موقت.'], sit_time: ['مدت SIT','برای این روش می‌توان مدت اصلی را تغییر داد.'],
    parallel: ['اجرای هم‌زمان','روش‌های هم‌زمان نرخ و حجم مجاز میزبان را با هم تقسیم می‌کنند.'],
  },
  settings: {
    port: ['پورت ورود پنل','درگاه HTTPS پنل. پنل منتظر تأیید اتصال تازه می‌ماند.'],
    username: ['نام کاربری','نامی که در فرم ورود استفاده می‌شود.'],
    ssh_ports: ['پورت‌های SSH','پورت‌های اضافه برای محافظت کنار پورت‌هایی که عامل خودکار تشخیص می‌دهد.'],
    reserved_ports: ['پورت‌های محفوظ','پورت‌هایی که باید برای سرویس‌های محلی آزاد بمانند.'],
    mtu: ['حد بالای MTU خودکار',mtuHint],
    retention_days: ['نگهداری آمار','تعداد روزهای نگهداری ریزنمونه‌های ترافیک.'],
    backup_keep: ['تعداد بکاپ‌ها','حداکثر شمار بکاپ‌هایی که پنل نگه می‌دارد.'],
    hostname: ['دامنه ورود','نام دامنه‌ای که کاربر برای ورود به پنل باز می‌کند.'],
    v2_limit_up: ['سقف ارسال میزبان',rateHints['rate-up'][1]], v2_limit_down: ['سقف دریافت میزبان',rateHints['rate-down'][1]],
    v2_conntrack_high: ['آستانه توقف اتصال تازه','در این درصد از ظرفیت conntrack، پذیرش اتصال تازه متوقف می‌شود.'],
    v2_conntrack_low: ['آستانه ازسرگیری','پس از افت اشغال جدول conntrack تا این درصد، پذیرش اتصال تازه برمی‌گردد.'],
    watchdog: ['بازیابی خودکار GRE','پس از سه بررسی ناموفق، عامل برای بازگردانی مسیر تلاش می‌کند.'],
  },
};

let nextHint = 0;
let visibleHint;
function closeFieldHint() {
  if (!visibleHint) return;
  visibleHint.tip.hidden = true;
  visibleHint.button.setAttribute('aria-expanded','false');
  visibleHint.pinned = false;
  visibleHint = undefined;
}
function showFieldHint(hint) {
  if (visibleHint === hint) return;
  closeFieldHint();
  visibleHint = hint;
  hint.tip.hidden = false;
  hint.button.setAttribute('aria-expanded','true');
}
function decorateFields(root, group) {
  for (const input of root.querySelectorAll('input:not([type=hidden]),select,textarea')) {
    const label = input.closest('label');
    const name = input.dataset.value || input.name;
    const entry = v2FieldSchema[group][name];
    if (!entry || !label || label.closest('.field-with-help')) continue;
    if ((group === 'group' && input.closest('[data-v2-listener]')) || (group === 'listener' && input.closest('[data-v2-member]'))) continue;
    const wrapper = document.createElement('div');
    const button = document.createElement('button');
    const tip = document.createElement('span');
    wrapper.className = 'field-with-help';
    button.className = 'field-help';
    tip.id = 'v2-field-help-' + ++nextHint;
    tip.setAttribute('role','tooltip');
    tip.textContent = entry[1];
    tip.hidden = true;
    button.type = 'button';
    button.textContent = '؟';
    button.setAttribute('aria-label','راهنمای ' + entry[0]);
    button.setAttribute('aria-expanded','false');
    button.setAttribute('aria-controls',tip.id);
    const described = input.getAttribute('aria-describedby');
    input.setAttribute('aria-describedby', [described,tip.id].filter(Boolean).join(' '));
    label.before(wrapper);
    wrapper.hidden = label.hidden;
    wrapper.append(label,button,tip);
    const help = {button,tip,wrapper,pinned:false};
    button.addEventListener('focus',() => showFieldHint(help));
    button.addEventListener('pointerenter',() => showFieldHint(help));
    button.addEventListener('pointerleave',() => {
      if (visibleHint === help && !help.pinned && document.activeElement !== button) closeFieldHint();
    });
    button.addEventListener('blur',() => { if (visibleHint === help && !help.pinned) closeFieldHint(); });
    button.addEventListener('click',() => {
      if (help.pinned) closeFieldHint();
      else { showFieldHint(help); help.pinned = true; }
    });
  }
}
document.addEventListener('pointerdown', event => {
  if (visibleHint && !visibleHint.wrapper.contains(event.target)) closeFieldHint();
});
document.addEventListener('keydown', event => {
  if (visibleHint && event.key === 'Escape') { closeFieldHint(); event.preventDefault(); }
});

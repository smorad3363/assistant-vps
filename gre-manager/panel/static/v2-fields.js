'use strict';

const rateHints = {
  'rate-up': ['سقف ارسال','حداکثر سرعت ارسال به مگابیت بر ثانیه. اگر خالی باشد، سقف جداگانه‌ای برای این بخش نمی‌گذاری.'],
  'rate-down': ['سقف دریافت','حداکثر سرعت دریافت به مگابیت بر ثانیه. اگر خالی باشد، سقف جداگانه‌ای برای این بخش نمی‌گذاری.'],
};
const mtuHint = 'بزرگ‌ترین اندازه بسته‌ای که از این تونل می‌گذرد، به بایت.';
const mssHint = 'اندازه بخش داده در بسته‌های TCP. حالت «از روی اندازه بسته» از MTU همین سمت استفاده می‌کند.';
const v2FieldSchema = {
  group: {
    name:['نام','یک اسم برای پیدا کردن این اتصال در فهرست بنویس.'],
    selection:['انتخاب مقصد','در تقسیم بار، سهم هر مسیر را تعیین می‌کنی. برای مسیر اصلی و پشتیبان، عدد اولویت کمتر یعنی انتخاب زودتر.'],
    enabled:['وضعیت','اگر خاموش باشد، این مسیر اتصال جدید نمی‌گیرد.'],
    ...rateHints,
  },
  listener: {
    node:['سرور ورودی','کاربرها به این سرور وصل می‌شوند.'],
    ip:['آی‌پی ورودی','آی‌پی روی سرور ورودی که در تنظیمات کاربران می‌نویسی. برای SIT این آدرس سمت ورودی تونل است.'],
    outer:['آی‌پی تونل در ورودی','اگر سرور چند آی‌پی دارد، آی‌پی ارتباط با سرور مقابل را بنویس. خالی یعنی همان آی‌پی ورودی.'],
    ports:['پورت‌های ورودی','یک پورت مثل 443، چند پورت با کاما، یک بازه مثل 8000-8100 یا «همه» را بنویس.'],
    excluded:['پورت‌های کنارگذاشته','این پورت‌ها روی سرور ورودی می‌مانند. پورت پنل و پورت‌های SSH خودکار کنار گذاشته می‌شوند.'],
    'override-port':['پورت ورودی','پورت سمت کاربر که می‌خواهی مقصد یا سرعتش را تغییر بدهی. این پورت باید در فهرست ورودی باشد.'],
    'override-target':['پورت مقصد','شماره پورتی که برنامه روی آن جواب می‌دهد. خالی یعنی همان شماره پورت ورودی.'],
    'override-up':['سقف ارسال پورت','حداکثر سرعت ارسال همین پورت به مگابیت بر ثانیه.'],
    'override-down':['سقف دریافت پورت','حداکثر سرعت دریافت همین پورت به مگابیت بر ثانیه.'],
    protocol:['نوع ترافیک','نوع اتصال مورد استفاده برنامه را انتخاب کن. اگر هر دو لازم است، TCP و UDP را با هم انتخاب کن.'],
    'watch-link':['تست تونل','وقتی روشن باشد، فقط تونلی که به تست جواب می‌دهد اتصال جدید می‌گیرد.'],
    'probe-protocol':['تست برنامه','پنل یک درخواست برای خود برنامه می‌فرستد و جوابش را بررسی می‌کند.'],
    'probe-port':['پورت تست','پورت سمت کاربر را بنویس. اگر شماره پورت در مقصد عوض می‌شود، پنل خودش آن را پیدا می‌کند.'],
    'probe-request':['درخواست تست','متنی که می‌خواهی پنل به برنامه بفرستد.'],
    'probe-response':['جواب تست','متنی که برنامه باید در جواب درخواست برگرداند.'],
    ...rateHints,
  },
  member: {
    node:['سرور مقصد','سروری را انتخاب کن که تونل به آن وصل می‌شود. در انتقال مستقیم می‌توانی فقط آی‌پی برنامه را بدهی.'],
    method:['روش اتصال','روش ارتباط ورودی با این مقصد. قبل از ذخیره، پنل تنظیمات دو سرور را بررسی می‌کند.'],
    service:['آی‌پی برنامه','آی‌پی که برنامه روی آن جواب می‌دهد. اگر برنامه روی آی‌پی اصلی سرور مقصد است، همان را وارد کن.'],
    outer:['آی‌پی تونل در مقصد','آی‌پی سرور مقابل برای ساخت تونل. برای SIT لازم است. در روش‌های دیگر، خالی یعنی همان آی‌پی برنامه.'],
    mtu:['اندازه بسته',mtuHint], ttl:['حد پرش','حداکثر تعداد عبور بسته از روترها. صفر یعنی از بسته داخل تونل گرفته شود.'],
    weight:['سهم مسیر','بین مقصدهای سالم با اولویت برابر، سهم بیشتر یعنی اتصال‌های جدید بیشتری به این مقصد می‌رسد.'],
    priority:['اولویت مسیر','عدد کمتر زودتر انتخاب می‌شود. مثلاً برای مسیر اصلی صفر و برای پشتیبان ۱۰ بگذار.'],
    state:['وضعیت مقصد','«فقط اتصال‌های فعلی» یعنی کاربران وصل می‌توانند ادامه بدهند و این مسیر کاربر جدید نمی‌گیرد.'],
    'vxlan-vni':['شناسه شبکه','یک شماره مشترک برای دو طرف شبکه VXLAN.'],
    'vxlan-port':['پورت تونل','پورت UDP مشترک دو طرف. پیش‌فرض 4789 است.'],
    'gretap-key':['کلید تونل','اگر خالی بگذاری، پنل کلید مشترک دو سرور را می‌سازد.'],
    'eoip-id':['شناسه تونل','عدد یکسانی برای تونل EoIP روی هر دو سرور بگذار.'],
    'ppp-lac':['شروع اتصال','سروری که اتصال PPP را به سرور مقابل شروع می‌کند.'],
    'ingress-ppp-port':['پورت ورودی','یک پورت UDP آزاد روی سرور ورودی برای L2TPv2.'],
    'destination-ppp-port':['پورت مقصد','یک پورت UDP آزاد روی سرور مقصد برای L2TPv2.'],
    'ingress-ppp-credential':['نام فایل رمز ورودی','نام فایل رمز PPP که روی سرور ورودی ذخیره شده است.'],
    'destination-ppp-credential':['نام فایل رمز مقصد','نام فایل رمز PPP که روی سرور مقصد ذخیره شده است.'],
    'ingress-sit-ip':['آدرس داخلی ورودی','آدرس IPv6 داخل تونل را با طول پیشوند وارد کن. مثلاً fd00::1/64.'],
    'destination-sit-ip':['آدرس داخلی مقصد','آدرس IPv6 متفاوتی از همان شبکه وارد کن. مثلاً fd00::2/64.'],
    'ingress-l2tp-tunnel_id':['شناسه تونل ورودی','شماره تونل L2TPv3 روی سرور ورودی.'],
    'destination-l2tp-tunnel_id':['شناسه تونل مقصد','شماره تونل L2TPv3 روی سرور مقصد.'],
    'ingress-l2tp-session_id':['شناسه اتصال ورودی','شماره اتصال داخل تونل روی سرور ورودی.'],
    'destination-l2tp-session_id':['شناسه اتصال مقصد','شماره اتصال داخل تونل روی سرور مقصد.'],
    'ingress-l2tp-port':['پورت ورودی','پورت UDP تونل روی سرور ورودی.'],
    'destination-l2tp-port':['پورت مقصد','پورت UDP تونل روی سرور مقصد.'],
    'geneve-vni':['شناسه شبکه','یک شماره مشترک برای دو طرف شبکه GENEVE.'],
    'geneve-port':['پورت تونل','پورت UDP مشترک دو طرف. پیش‌فرض 6081 است.'],
    'ingress-mtu':['اندازه بسته در ورودی',mtuHint], 'destination-mtu':['اندازه بسته در مقصد',mtuHint],
    'ingress-mode':['روش تنظیم MSS در ورودی',mssHint], 'destination-mode':['روش تنظیم MSS در مقصد',mssHint],
    'ingress-mss':['مقدار دستی MSS در ورودی',mssHint], 'destination-mss':['مقدار دستی MSS در مقصد',mssHint],
    'ingress-wg-key':['کلید عمومی ورودی','کلید عمومی WireGuard ساخته‌شده روی سرور ورودی.'],
    'destination-wg-key':['کلید عمومی مقصد','کلید عمومی WireGuard ساخته‌شده روی سرور مقصد.'],
    'ingress-wg-port':['پورت ورودی','پورت UDP روی سرور ورودی برای WireGuard.'],
    'destination-wg-port':['پورت مقصد','پورت UDP روی سرور مقصد برای WireGuard.'],
    keepalive:['فاصله پیام‌ها','هر چند ثانیه یک پیام برای باز نگه داشتن اتصال فرستاده شود؟ صفر یعنی خاموش.'],
    ...rateHints,
  },
  benchmark: {
    first_node:['سرور اول','تست رفت از این سرور شروع می‌شود.'], second_node:['سرور دوم','تست برگشت از این سرور شروع می‌شود.'],
    first:['آی‌پی اول','آی‌پی روی سرور اول که با آن تست می‌کنی.'], second:['آی‌پی دوم','آی‌پی روی سرور دوم که با آن تست می‌کنی.'],
    duration_s:['مدت هر تست','مجموع زمان رفت و برگشت یک روش، به ثانیه. آماده شدن سرورها جدا حساب می‌شود.'],
    gre:['GRE','یک تونل موقت GRE برای تست می‌سازد.'], ipip:['IPIP','ارتباط IPv4 داخل IPv4 را تست می‌کند.'],
    gre_time:['زمان GRE','اگر خالی باشد، همان مدت اصلی تست استفاده می‌شود.'], ipip_time:['زمان IPIP','اگر خالی باشد، همان مدت اصلی تست استفاده می‌شود.'],
    sit:['SIT','داده IPv6 را داخل یک تونل موقت SIT تست می‌کند.'], sit_time:['زمان SIT','اگر خالی باشد، همان مدت اصلی تست استفاده می‌شود.'],
    parallel:['تست هم‌زمان','اگر روشن باشد، روش‌ها سرعت و حجم تست را بین خودشان تقسیم می‌کنند.'],
  },
  settings: {
    port:['پورت ورود پنل','بعد از تغییر پورت، از آدرس جدید وارد پنل شو تا تغییر ثبت شود.'],
    username:['نام کاربری','با این نام وارد پنل می‌شوی.'],
    ssh_ports:['پورت‌های SSH','پنل پورت‌های SSH را پیدا می‌کند. پورت‌های مدیریت اضافی را هم می‌توانی اینجا بنویسی.'],
    reserved_ports:['پورت‌های محلی','این پورت‌ها برای برنامه‌های خود سرور می‌مانند.'],
    mtu:['حداکثر اندازه بسته',mtuHint], retention_days:['مدت نگهداری آمار','جزئیات مصرف چند روز روی سرور بماند؟'],
    telemetry_limit_mib:['فضای آمار','حداکثر فضای دیسک برای آمار. وقتی پُر شود، قدیمی‌ترین جزئیات پاک می‌شود.'],
    backup_keep:['تعداد بکاپ‌ها','چند بکاپ آخر را روی این سرور نگه داریم؟'],
    backup_limit_mib:['فضای بکاپ‌ها','حداکثر فضا برای همه بکاپ‌ها. جدیدترین بکاپ در اولویت است.'],
    hostname:['دامنه ورود','دامنه‌ای که در مرورگر برای ورود به پنل می‌نویسی.'],
    v2_limit_up:['سقف ارسال سرور',rateHints['rate-up'][1]], v2_limit_down:['سقف دریافت سرور',rateHints['rate-down'][1]],
    v2_conntrack_high:['توقف اتصال جدید','وقتی جدول اتصال‌های سرور تا این درصد پُر شود، پنل اتصال جدید را موقتاً متوقف می‌کند.'],
    v2_conntrack_low:['پذیرش دوباره','وقتی جدول اتصال‌ها تا این درصد خالی‌تر شد، پنل دوباره اتصال جدید می‌گیرد.'],
    watchdog:['ترمیم خودکار تونل','اگر تونل سه بار جواب ندهد، پنل تنظیمات همان تونل را دوباره اجرا می‌کند.'],
  },
};

function isolateTechnical(root) {
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT);
  const nodes = [];
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (!node.parentElement.closest('bdi,code,svg,script,style,textarea,option,[dir=ltr]') && /[a-zA-Z]|[0-9]+[.:/,-][0-9]+/.test(node.data))
      nodes.push(node);
  }
  for (const node of nodes) {
    const fragment = document.createDocumentFragment();
    let start = 0;
    for (const token of node.data.matchAll(/(?:[a-zA-Z][a-zA-Z0-9_.+/-]*|[0-9]+(?:[.:/,-][0-9]+)+)/g)) {
      fragment.append(node.data.slice(start,token.index));
      const word = document.createElement('bdi');
      word.dir = 'ltr';
      word.textContent = token[0];
      fragment.append(word);
      start = token.index + token[0].length;
    }
    fragment.append(node.data.slice(start));
    node.replaceWith(fragment);
  }
}
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
    const caption = document.createElement('span');
    if (input.type !== 'checkbox' && input.parentElement === label) {
      while (label.firstChild && label.firstChild !== input) caption.append(label.firstChild);
      if (caption.textContent.trim()) {
        caption.className = 'field-caption';
        label.prepend(caption);
        wrapper.classList.add('captioned');
      }
    }
    wrapper.append(label,button,tip);
    isolateTechnical(wrapper);
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

'use strict';
const $ = (q, root = document) => root.querySelector(q);
const $$ = (q, root = document) => [...root.querySelectorAll(q)];
const fa = new Intl.NumberFormat('fa-IR', {maximumFractionDigits: 1});
const latin = new Intl.NumberFormat('en-US', {maximumFractionDigits: 1});
const clock = new Intl.DateTimeFormat('fa-IR', {timeZone:'Asia/Tehran', hour:'2-digit', minute:'2-digit'});
const esc = x => String(x ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const icon = name => `<svg class="icon" aria-hidden="true"><use href="#i-${name}"/></svg>`;
let state, csrf = '', page = 'gre', toastTimer, activeJob = null;
const expanded = new Set();
const errors = {
  auth:'اطلاعات ورود درست نیست یا نشست منقضی شده است.', csrf:'نشست صفحه تازه نیست؛ صفحه را دوباره بارگذاری کن.',
  rate_limit:'تعداد تلاش‌های ورود زیاد شده؛ پنج دقیقه دیگر تلاش کن.',
  overlap:'پورت‌های این اتصال با اتصال دیگری هم‌پوشانی دارند. ابتدا پورت را از اتصال قبلی جدا کن.',
  reserved:'یکی از پورت‌ها برای ورود پنل یا SSH محفوظ است. پورت دیگری انتخاب کن.',
  local_ip:'IP ورودی باید روی همین سرور ایران فعال باشد.', loop:'مقصد انتقال مستقیم نمی‌تواند خود سرور ورودی باشد.',
  dns:'دامنه مقصد به IPv4 معتبر تبدیل نشد. آدرس و DNS را بررسی کن.',
  server:'ابتدا یک سرور خارج را در پنل متصل و انتخاب کن.',
  ssh:'اتصال SSH یا آماده‌سازی خارج انجام نشد. آدرس، پورت و دسترسی root یا sudo را بررسی کن.',
  ssh_key:'کلید مدیریت این سرور موجود نیست؛ سرور خارج را دوباره اضافه کن و در اتصال انتخاب کن.',
  gre_probe:'پاسخ GRE دریافت نشد؛ دسترسی پروتکل ۴۷ و مسیر دو سرور را بررسی کن. تنظیم قبلی بازیابی می‌شود.',
  external_conflict:'یک انتقال خارج از مدیریت این پنل با پورت‌های انتخابی تداخل دارد. پیش از ادامه باید جداگانه منتقل شود.',
  device_conflict:'رابط هم‌نام متعلق به تنظیم دیگری است و تغییر داده نشد.', route_conflict:'آدرس داخلی GRE با یک مسیر موجود تداخل دارد.',
  recovering:'بازیابی تغییر قبلی هنوز تمام نشده است. کمی صبر کن.', busy:'عملیات دیگری در خارج در حال انجام است؛ کمی صبر کن.',
  port_in_use:'پورت انتخابی پنل در حال استفاده است.', in_use:'این سرور هنوز در یک اتصال GRE استفاده می‌شود.',
  certificate:'گواهی و کلید خصوصی با هم سازگار نیستند یا فایل‌ها معتبر نیستند.', password:'رمز جدید باید بین ۱۲ تا ۲۵۶ کاراکتر باشد.',
  unavailable:'سرویس مدیریت در حال راه‌اندازی مجدد است؛ چند لحظه دیگر تلاش می‌کنیم.', not_found:'این مورد دیگر موجود نیست.'
};

function bytes(value) {
  let n = Number(value) || 0, i = 0;
  const units = ['B','KB','MB','GB','TB'];
  while (n >= 1024 && i < 4) { n /= 1024; i++; }
  return `${latin.format(n)} ${units[i]}`;
}
function speed(value) { return latin.format((Number(value) || 0) / 1e6); }
function when(value) { return value ? clock.format(new Date(value * 1000)) : '—'; }
function failText(error) {
  if (errors[error.code]) return errors[error.code];
  const text = String(error.error || error.message || '');
  if (/port range|ports|port mapping|Port translation/i.test(text)) return 'فهرست پورت‌ها را بررسی کن. برای تغییر پورت مقصد، یک پورت ورودی انتخاب کن.';
  if (/hostname|IPv4|unicast|address/i.test(text)) return 'آدرس واردشده معتبر نیست. IP یا دامنه را بدون http و شماره پورت وارد کن.';
  if (/whole number|between|speed|number/i.test(text)) return 'مقدار عددی را در محدوده مجاز وارد کن.';
  if (/corrupt|backup|archive|telemetry/i.test(text)) return 'فایل پشتیبان معتبر نیست یا امکان بازیابی آن وجود ندارد.';
  if (/password/i.test(text)) return 'رمز عبور را بررسی کن؛ رمز جدید باید حداقل ۱۲ کاراکتر باشد.';
  if (/protocol/i.test(text)) return 'حداقل یکی از پروتکل‌های TCP و UDP را انتخاب کن.';
  return 'عملیات انجام نشد. وضعیت اتصال و مقادیر واردشده را بررسی کن.';
}
function eventText(message) {
  const pairs = [
    ['Existing GRE pairs imported','تونل‌های قبلی شناسایی شدند؛ مقدارهای فعلی حفظ شده‌اند.'],
    ['Network configuration saved','تنظیمات اتصال ذخیره و اعمال شد.'],
    ['Foreign server connected','سرور خارج با کلید مدیریت اختصاصی متصل شد.'],
    ['Previous network settings restored','تغییر ناموفق بود؛ تنظیمات قبلی بازیابی شد.'],
    ['Local rollback completed','تنظیمات ایران بازیابی شد؛ بازیابی خارج دوباره تلاش می‌شود.'],
    ['Owned GRE state refreshed','پس از سه بررسی ناموفق، تنظیمات GRE تازه‌سازی شد.'],
    ['Panel port change rolled back','ورود در پورت جدید تأیید نشد؛ پورت قبلی پنل بازیابی شد.'],
    ['Update scheduled','به‌روزرسانی برنامه زمان‌بندی شد.'],
  ];
  for (const [prefix, copy] of pairs) if (message.startsWith(prefix)) return copy;
  return failText({message});
}
async function api(route, payload, options = {}) {
  const read = payload === undefined;
  let url = '/api/' + route;
  if (options.query) url += '?' + new URLSearchParams(options.query);
  const response = await fetch(url, {method:read ? 'GET':'POST', credentials:'same-origin',
    headers: read ? {} : {'Content-Type':'application/json','X-Gremgr-CSRF':csrf},
    body: read ? undefined : JSON.stringify(payload)});
  const data = await response.json();
  if (!response.ok) { const e = Object.assign(new Error(failText(data)), data); e.status = response.status; throw e; }
  return data;
}
function showToast(text) {
  clearTimeout(toastTimer); $('#toast').textContent = text; $('#toast').hidden = false;
  toastTimer = setTimeout(() => { $('#toast').hidden = true; }, 4200);
}
function showLogin() { $('#app').hidden = true; $('#login-view').hidden = false; }
function setError(form, error) {
  $('.form-error', form).textContent = failText(error);
  $$('[aria-invalid]', form).forEach(x => x.removeAttribute('aria-invalid'));
  if (error.field && form.elements[error.field] instanceof HTMLElement) {
    form.elements[error.field].setAttribute('aria-invalid','true'); form.elements[error.field].focus();
  }
}
function setBusy(form, value) {
  const button = $('button[type=submit]', form);
  button.disabled = value;
  if (value) { button.dataset.label = button.textContent; button.textContent = 'در حال بررسی…'; }
  else if (button.dataset.label) button.textContent = button.dataset.label;
}

async function refresh(quiet = false) {
  try {
    state = await api('state'); csrf = state.csrf;
    $('#login-view').hidden = true; $('#app').hidden = false;
    $('#sync-state').classList.toggle('stale', !state.sampled_at || Date.now()/1000 - state.sampled_at > 20);
    $('#sync-state span').textContent = state.sampled_at ? 'به‌روز · ' + when(state.sampled_at) : 'آمار در حال آماده‌شدن';
    $('#recovery-alert').hidden = !state.recovering;
    $('#footer-sample').textContent = state.sampled_at ? 'آخرین نمونه: ' + when(state.sampled_at) : 'منتظر اولین نمونه آمار';
    render();
    if (!quiet) await api('web.confirm', {port: Number(location.port) || (location.protocol === 'https:' ? 443 : 80)});
  } catch (e) {
    if (e.status === 401) showLogin();
    else { $('#sync-state').classList.add('stale'); $('#sync-state span').textContent = 'ارتباط پنل قطع است'; if (!quiet) showToast(failText(e)); }
  }
}

function navigate() {
  page = ['gre','direct','settings'].includes(location.hash.slice(1)) ? location.hash.slice(1) : 'gre';
  $$('.tabs a').forEach(x => { if(x.dataset.page === page) x.setAttribute('aria-current','page'); else x.removeAttribute('aria-current'); });
  $('#connections-page').hidden = page === 'settings'; $('#settings-page').hidden = page !== 'settings';
  if (page !== 'settings') {
    const gre = page === 'gre';
    $('#page-title').textContent = gre ? 'تونل‌های GRE' : 'انتقال مستقیم';
    $('#page-eyebrow').textContent = gre ? 'اتصال بین دو سرور' : 'IPTABLES';
    $('#page-description').textContent = gre ? 'وضعیت مسیرها و ترافیک، در یک نگاه.' : 'انتقال پورت‌های ایران به IP یا دامنه مقصد.';
    $('#add-connection span').textContent = gre ? 'افزودن GRE' : 'افزودن انتقال';
  }
  if (state) render();
}

function render() {
  $('#gre-count').textContent = fa.format(state.connections.filter(x=>x.kind==='gre').length);
  $('#direct-count').textContent = fa.format(state.connections.filter(x=>x.kind==='direct').length);
  $('#version').textContent = 'v' + state.version;
  if (page === 'settings') return renderSettings();
  const items = state.connections.filter(x=>x.kind === page);
  const ids = new Set(items.map(x=>x.id));
  $('#metric-active').textContent = fa.format(items.filter(x=>x.enabled).length);
  $('#metric-total').textContent = 'از ' + fa.format(items.length) + ' اتصال ثبت‌شده';
  $('#metric-down').textContent = speed(items.reduce((n,x)=>n+x.rate.down,0));
  $('#metric-up').textContent = speed(items.reduce((n,x)=>n+x.rate.up,0));
  $('#metric-usage').textContent = bytes(state.stats.today.filter(x=>ids.has(x.identity)).reduce((n,x)=>n+x.up+x.down,0));
  renderConnections(items); renderChart(ids); renderEvents();
}

function statusFor(c) {
  if (!c.enabled) return ['paused','متوقف'];
  const value = c.kind === 'gre' ? c.health?.gre : c.health?.tcp;
  if (value === true) return ['','بررسی شد'];
  if (value === false) return ['error',c.kind === 'gre'?'بدون پاسخ GRE':'بدون پاسخ TCP'];
  return ['warning','فعال · بررسی نشده'];
}
function totalFor(id, port = 'all') { return state.stats.totals.find(x=>x.identity===id && x.port===String(port)) || {up:0,down:0}; }
function renderConnections(items) {
  const list = $('#connection-list');
  if (!items.length) {
    list.innerHTML = `<div class="empty"><div class="empty-icon">${icon(page==='gre'?'link':'route')}</div><h2>هنوز اتصالی اضافه نشده</h2><p>${page==='gre'?'سرور خارج را متصل کن و اولین تونل را بساز.':'مقصد و پورت‌ها را وارد کن؛ آماده‌سازی روی ایران انجام می‌شود.'}</p><button class="button secondary" data-action="add">${icon('plus')}افزودن اولین اتصال</button></div>`;
    return;
  }
  $('.empty',list)?.remove();
  $$('.connection',list).forEach(x=>{if(!items.some(c=>c.id===x.dataset.id))x.remove();});
  for (const c of items) {
    let row = $(`.connection[data-id="${c.id}"]`, list);
    if (!row) {row=document.createElement('article');row.className='connection';row.dataset.id=c.id;list.append(row);}
    if (row.contains(document.activeElement)) continue;
    row.classList.toggle('paused',!c.enabled);
    const [style,status] = statusFor(c), total = totalFor(c.id);
    row.innerHTML = `<div class="connection-row"><div class="connection-title"><div class="connection-avatar">${icon(c.kind==='gre'?'link':'route')}</div><div><h3 class="connection-name">${esc(c.name)}</h3><div class="connection-meta"><span class="status ${style}"><i></i>${status}</span>${c.kind==='gre'?`<code dir="ltr">MTU ${esc(c.mtu)}</code>`:`<code dir="ltr">${c.protocols.map(x=>x.toUpperCase()).join(' + ')}</code>`}</div></div></div>
      <div class="destination"><div class="path-end" dir="ltr"><span>${esc(c.listen_ip)}</span></div><div class="path-end secondary-value" dir="ltr">${icon('arrow')}<span>${esc(c.target_host)}</span></div></div>
      <div class="ports-cell"><span class="data-label">پورت‌ها</span><span class="ports-badge" dir="ltr" title="${esc(c.ports)}">${c.ports==='all'?'همه پورت‌ها':esc(c.ports)}</span></div>
      <div class="speed-cell"><span class="data-label">دریافت / ارسال · Mbps</span><div class="speed-value"><span class="down">${speed(c.rate.down)}</span><span>/</span><span class="up">${speed(c.rate.up)}</span></div></div>
      <div class="usage-cell"><span class="data-label">مصرف کل</span><span class="data-value" dir="ltr">${bytes(total.up+total.down)}</span></div>
      <div class="row-actions"><button class="icon-button probe-button" data-action="probe" aria-label="تست اتصال ${esc(c.name)}" title="تست اتصال">${icon('refresh')}</button><button class="icon-button" data-action="edit" aria-label="ویرایش ${esc(c.name)}" title="ویرایش">${icon('edit')}</button><button class="icon-button" data-action="toggle" aria-label="${c.enabled?'توقف':'راه‌اندازی'} ${esc(c.name)}" title="${c.enabled?'توقف':'راه‌اندازی'}">${icon('power')}</button><button class="icon-button delete" data-action="delete" aria-label="حذف ${esc(c.name)}" title="حذف">${icon('trash')}</button><button class="icon-button expand-button" data-action="expand" aria-label="جزئیات ${esc(c.name)}" aria-expanded="${expanded.has(c.id)}">${icon('chevron')}</button></div></div>
      <div class="connection-details" ${expanded.has(c.id)?'':'hidden'}>${detailsFor(c)}</div>`;
  }
}

function detailsFor(c) {
  const total=totalFor(c.id), limit=v=>v?`${latin.format(v)} Mbps`:'نامحدود';
  const health = value => value===true?'پاسخ دریافت شد':value===false?'بدون پاسخ':'بررسی نشده';
  const metrics = [['IP فعلی مقصد',c.resolved_ip],['سقف دریافت',limit(c.download_mbps)],['سقف ارسال',limit(c.upload_mbps)],['مصرف کل',bytes(total.up+total.down)],
    ...(c.kind==='gre'?[['پینگ GRE',c.health?.latency_ms!=null?latin.format(c.health.latency_ms)+' ms':'بررسی نشده'],['افت بسته',c.health?.loss_percent!=null?latin.format(c.health.loss_percent)+'%':'بررسی نشده']]:[]),['سرویس TCP',health(c.health?.tcp)],['سرویس UDP',health(c.health?.udp)]];
  let output = `<div class="detail-grid">${metrics.map(([label,value])=>`<div><span class="data-label">${esc(label)}</span><span class="detail-value">${esc(value)}</span></div>`).join('')}</div>`;
  const ports=state.stats.totals.filter(x=>x.identity===c.id&&x.port!=='all');
  if(ports.length) output+=`<table class="detail-table"><thead><tr><th>پورت ورودی</th><th>ارسال</th><th>دریافت</th></tr></thead><tbody>${ports.map(x=>`<tr><td>${esc(x.port)}</td><td dir="ltr">${bytes(x.up)}</td><td dir="ltr">${bytes(x.down)}</td></tr>`).join('')}</tbody></table>`;
  const map=Object.entries(c.port_map||{}); if(map.length)output+=`<p class="detail-note">نگاشت‌ها: <bdi dir="ltr">${map.map(([a,b])=>esc(a+':'+b)).join(' · ')}</bdi></p>`;
  output+=`<p class="detail-note">تست UDP فقط با پاسخ واقعی سرویس تأیید می‌شود. آمار «همه پورت‌ها» مجموع اتصال است؛ پورت‌های انتخاب‌شده در جزئیات تفکیک می‌شوند.</p><button class="button secondary compact" data-action="probe">${icon('refresh')}بررسی دوباره اتصال</button>`;
  return output;
}

function renderChart(ids) {
  const target=$('#traffic-chart');
  // State also includes per-connection points so the two pages never mix traffic.
  const selected=state.stats.series?.filter(x=>ids.has(x.identity)) || [];
  const grouped=new Map();
  for(const p of selected){const x=grouped.get(p.at)||{at:p.at,up:0,down:0};x.up+=p.up;x.down+=p.down;grouped.set(p.at,x);}
  const points=[...grouped.values()].sort((a,b)=>a.at-b.at);
  if(points.length<2){target.innerHTML='<div class="chart-empty">پس از ثبت نمونه‌های مصرف، نمودار اینجا نمایش داده می‌شود.</div>';return;}
  const W=1000,H=160,left=65,right=12,top=8,bottom=26,max=Math.max(1024,...points.map(x=>Math.max(x.up,x.down)));
  const start=Date.now()/1000-86400,end=Date.now()/1000;
  const x=t=>left+(t-start)/(end-start)*(W-left-right),y=n=>top+(1-n/max)*(H-top-bottom);
  const line=key=>points.map((p,i)=>(i?'L':'M')+x(p.at).toFixed(1)+','+y(p[key]).toFixed(1)).join(' ');
  const ticks=[0,.5,1].map(f=>`<line x1="${left}" x2="${W-right}" y1="${y(max*f)}" y2="${y(max*f)}" stroke="#2b3830" stroke-dasharray="3 5"/><text x="${left-9}" y="${y(max*f)+3}" text-anchor="end">${esc(bytes(max*f))}</text>`).join('');
  const times=[0,.25,.5,.75,1].map(f=>`<text x="${x(start+(end-start)*f)}" y="${H-2}" text-anchor="${f===0?'start':f===1?'end':'middle'}">${esc(when(start+(end-start)*f))}</text>`).join('');
  target.innerHTML=`<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="نمودار حجم ارسال و دریافت در ۲۴ ساعت گذشته؛ واحد بایت در دقیقه" preserveAspectRatio="none">${ticks}<path d="${line('down')}" fill="none" stroke="#9ce0c4" stroke-width="1.8" vector-effect="non-scaling-stroke"/><path d="${line('up')}" fill="none" stroke="#9baed1" stroke-width="1.5" vector-effect="non-scaling-stroke"/>${times}</svg>`;
}
function renderEvents() {
  $('#events-list').innerHTML=state.events.length?state.events.slice(0,5).map(x=>`<div class="event ${esc(x.kind)}"><i class="dot"></i><span class="event-message">${esc(eventText(x.message))}</span><time>${when(x.at)}</time></div>`).join(''):'<p class="empty-line">رویداد تازه‌ای ثبت نشده است.</p>';
}
function renderSettings() {
  const form=$('#settings-form');
  if(!form.dataset.dirty && !form.contains(document.activeElement))for(const [key,value]of Object.entries(state.settings)){const el=form.elements[key];if(!el)continue;if(el.type==='checkbox')el.checked=value;else el.value=Array.isArray(value)?value.join(','):value;}
  $('#server-list').innerHTML=state.servers.length?state.servers.map(s=>`<div class="server-item" data-server="${s.id}"><div class="connection-avatar">${icon('server')}</div><div class="server-info"><strong>${esc(s.name)}</strong><small dir="ltr">${esc(s.host)}:${esc(s.port)} · ${esc(s.username)}</small><span class="status ${s.key_ready?'':'warning'}"><i></i>${s.key_ready?'کلید مدیریت آماده است':'نیاز به اتصال مجدد'}</span><details><summary>اثر انگشت سرور</summary><bdi dir="ltr">${(s.fingerprints||[]).map(esc).join('<br>')}</bdi></details></div><button class="icon-button" data-action="delete-server" aria-label="حذف سرور ${esc(s.name)}">${icon('trash')}</button></div>`).join(''):'<p class="empty-line">سروری برای مدیریت GRE اضافه نشده است.</p>';
  $('#backup-list').innerHTML=state.backups.length?state.backups.map(name=>`<div class="backup-row"><code dir="ltr">${esc(name)}</code><a class="button compact secondary" href="/api/backup.download?filename=${encodeURIComponent(name)}" download>${icon('down')}دانلود</a></div>`).join(''):'<p class="empty-line">بکاپ‌ها پس از اولین ثبت یا پشتیبان‌گیری روزانه اینجا نمایش داده می‌شوند.</p>';
}

function fillServers(selected='') {
  const select=$('#connection-form').elements.server_id;
  select.innerHTML='<option value="">انتخاب سرور خارج</option>'+state.servers.map(s=>`<option value="${s.id}">${esc(s.name)} · ${esc(s.host)}</option>`).join('');
  select.value=selected;
}
function portLimitRow(port='',up=0,down=0) {
  const row=document.createElement('div');row.className='port-limit-row';
  row.innerHTML=`<label>پورت<input data-limit="port" type="number" min="1" max="65535" dir="ltr" value="${esc(port)}" required></label><label>ارسال · Mbps<input data-limit="up" type="number" min="0" step="0.001" dir="ltr" value="${esc(up)}"></label><label>دریافت · Mbps<input data-limit="down" type="number" min="0" step="0.001" dir="ltr" value="${esc(down)}"></label><button type="button" class="icon-button" data-action="remove-limit" aria-label="حذف محدودیت پورت">${icon('trash')}</button>`;
  $('#port-limit-rows').append(row);
}
function openConnection(c) {
  const form=$('#connection-form');form.reset();$('.form-error',form).textContent='';
  const kind=c?.kind || page; form.elements.kind.value=kind;form.elements.id.value=c?.id||'';
  $('#connection-title').textContent=c?'ویرایش اتصال':kind==='gre'?'افزودن GRE':'افزودن انتقال مستقیم';
  $('#connection-kicker').textContent=c?c.name:'اتصال جدید';
  $$('.gre-only',form).forEach(el=>{el.hidden=kind!=='gre';$$('input,select',el).forEach(x=>x.disabled=kind!=='gre');});
  const addresses=Object.keys(state.addresses);
  for(const field of ['listen_ip','outer_local'])form.elements[field].innerHTML=addresses.map(ip=>`<option value="${esc(ip)}">${esc(ip)} · ${esc(state.addresses[ip])}</option>`).join('');
  fillServers(c?.server_id||'');
  for(const key of ['name','target_host','target_port','upload_mbps','download_mbps','mtu_mode','service_ip'])if(c?.[key]!=null)form.elements[key].value=c[key];
  form.elements.listen_ip.value=c?.listen_ip||addresses[0]||'';
  form.elements.outer_local.value=c?.outer_local||c?.listen_ip||addresses[0]||'';
  form.elements.mtu.value=c?.mtu||state.settings.mtu;
  form.elements.mtu_mode.value=c?.mtu_mode||'auto';
  form.elements.upload_mbps.value=c?.upload_mbps||0;form.elements.download_mbps.value=c?.download_mbps||0;
  form.elements.proto_tcp.checked=c?c.protocols.includes('tcp'):true;form.elements.proto_udp.checked=c?c.protocols.includes('udp'):true;
  form.elements.port_mode.value=(!c||c.ports==='all')?'all':'selected';form.elements.ports.value=c?.ports==='all'?'':c?.ports||'';
  form.elements.exclude_ports.value=(c?.exclude_ports||[]).join(',');form.elements.monitor_ports.value=(c?.monitor_ports||[]).join(',');
  form.elements.port_map.value=Object.entries(c?.port_map||{}).map(([a,b])=>a+':'+b).join(',');
  $('#port-limit-rows').replaceChildren();for(const [p,v]of Object.entries(c?.port_limits||{}))portLimitRow(p,v.up,v.down);
  $('details',form).open=false;
  $('#protected-hint').textContent='پورت‌های محفوظ: '+[...new Set([22,state.settings.port,...state.settings.ssh_ports,...state.settings.reserved_ports])].join('، ');
  $('#target-label').textContent=kind==='gre'?'IP یا دامنه انتهای GRE':'IP یا دامنه مقصد';
  form.elements.server_id.required=kind==='gre'&&!c?.adopted;
  togglePortInputs();$('#connection-dialog').showModal();
}
function togglePortInputs(){const form=$('#connection-form');const all=form.elements.port_mode.value==='all';$('#port-inputs').hidden=all;form.elements.ports.required=!all;form.elements.target_port.disabled=all;}
async function confirmAction(title,text,button='تأیید',danger=true){
  const dialog=$('#confirm-dialog');$('#confirm-title').textContent=title;$('#confirm-text').textContent=text;$('#confirm-submit').textContent=button;$('#confirm-submit').className='button '+(danger?'danger':'primary');dialog.returnValue='';dialog.showModal();
  return new Promise(resolve=>dialog.addEventListener('close',()=>resolve(dialog.returnValue==='ok'),{once:true}));
}
async function runJob(route,payload,form,dialog) {
  if(form)setBusy(form,true);
  try{
    const reply=await api(route,payload);
    if(dialog)dialog.close();if(form)$('.form-error',form).textContent='';
    activeJob=reply.job;sessionStorage.setItem('gremgr_job',activeJob);pollJob(activeJob);
    return reply.job;
  }catch(e){if(form)setError(form,e);else showToast(failText(e));return null;}
  finally{if(form)setBusy(form,false);}
}
const jobMessages={'Queued':'در صف انجام','Checking configuration':'بررسی تنظیمات و تداخل پورت‌ها','Checking SSH host keys and credentials':'بررسی SSH و آماده‌سازی سرور خارج','Preparing foreign servers':'آماده‌سازی سمت خارج','Applying scoped network rules':'اعمال تنظیمات اتصال','Checking GRE and MTU':'بررسی ارتباط GRE و MTU','Committing both endpoints':'ذخیره نهایی در هر دو سرور'};
async function pollJob(identity){
  $('#job-status').hidden=false;$('#job-dismiss').hidden=true;$('#job-status').classList.remove('failed');
  try{
    const job=await api('job',undefined,{query:{id:identity}});$('#job-progress').value=job.progress;
    if(['done','failed','interrupted'].includes(job.status)){
      sessionStorage.removeItem('gremgr_job');activeJob=null;$('#job-dismiss').hidden=false;
      $('#job-title').textContent=job.status==='done'?'تغییرات انجام شد':'عملیات کامل نشد';
      $('#job-status').classList.toggle('failed',job.status!=='done');
      $('#job-message').textContent=job.status==='done'?'تنظیمات ثبت شد.':failText({error:job.message,code:job.result?.code});
      await refresh(true);
      if(job.result?.server){fillServers(job.result.server);const s=state.servers.find(x=>x.id===job.result.server);if(s&&$('#connection-dialog').open)$('#connection-form').elements.target_host.value=s.host;}
      if(job.result?.reconnect){const url=new URL(location.href);url.port=job.result.port;$('#job-message').replaceChildren(document.createTextNode('برای تأیید ورود، پورت جدید را باز کن: '));const a=document.createElement('a');a.href=url.href;a.textContent='ورود به پنل';a.className='button compact secondary';$('#job-message').append(a);}
      if(job.result?.paused_gre)showToast('اتصال‌های GRE فاقد کلید مدیریت، متوقف بازیابی شدند؛ سرور خارج را دوباره متصل کن.');
      if(job.status==='done'&&!job.result?.reconnect)setTimeout(()=>{if(!activeJob)$('#job-status').hidden=true;},6500);
      return;
    }
    $('#job-title').textContent='در حال اعمال تغییرات';$('#job-message').textContent=jobMessages[job.message]||'عملیات در پس‌زمینه ادامه دارد؛ بستن صفحه آن را متوقف نمی‌کند.';
  }catch(e){$('#job-message').textContent='منتظر اتصال دوباره به سرویس مدیریت…';}
  setTimeout(()=>{if(activeJob===identity)pollJob(identity);},1500);
}

$('#login-form').addEventListener('submit',async e=>{e.preventDefault();const form=e.currentTarget;setBusy(form,true);try{const reply=await api('login',Object.fromEntries(new FormData(form)));csrf=reply.csrf;form.elements.password.value='';$('#login-error').textContent='';await refresh();}catch(error){$('#login-error').textContent=failText(error);}finally{setBusy(form,false);}});
$('#logout').addEventListener('click',async()=>{await api('logout',{});csrf='';state=null;showLogin();});
$('#refresh').addEventListener('click',()=>refresh());
$('#add-connection').addEventListener('click',()=>openConnection());
$('#add-port-limit').addEventListener('click',()=>portLimitRow());
$('#connection-form').addEventListener('change',e=>{
  const form=e.currentTarget;if(e.target.name==='port_mode')togglePortInputs();
  if(e.target.name==='server_id'){const s=state.servers.find(x=>x.id===e.target.value);if(s)form.elements.target_host.value=s.host;}
  if(e.target.name==='listen_ip'&&!form.elements.id.value)form.elements.outer_local.value=e.target.value;
});
$('#connection-form').addEventListener('submit',async e=>{
  e.preventDefault();const form=e.currentTarget,p=Object.fromEntries(new FormData(form));
  if(!p.id)delete p.id;p.enabled=state.connections.find(x=>x.id===p.id)?.enabled??true;
  p.protocols=[...(form.elements.proto_tcp.checked?['tcp']:[]),...(form.elements.proto_udp.checked?['udp']:[])];
  p.ports=p.port_mode==='all'?'all':p.ports;p.exclude_ports=p.exclude_ports.split(',').map(x=>x.trim()).filter(Boolean);p.monitor_ports=p.monitor_ports.split(',').map(x=>x.trim()).filter(Boolean);
  p.port_limits={};for(const row of $$('.port-limit-row',form)){const port=$('[data-limit=port]',row).value;if(p.port_limits[port]){setError(form,{message:'ports'});return;}p.port_limits[port]={up:$('[data-limit=up]',row).value,down:$('[data-limit=down]',row).value};}
  await runJob('connection.save',p,form,$('#connection-dialog'));
});
$('#server-form').addEventListener('submit',async e=>{e.preventDefault();const form=e.currentTarget;const id=await runJob('server.connect',Object.fromEntries(new FormData(form)),form,$('#server-dialog'));if(id){form.elements.password.value='';form.elements.private_key.value='';}});
$('#settings-form').addEventListener('input',e=>e.currentTarget.dataset.dirty='true');
$('#settings-form').addEventListener('submit',async e=>{e.preventDefault();const form=e.currentTarget,p=Object.fromEntries(new FormData(form));p.watchdog=form.elements.watchdog.checked;const id=await runJob('settings.save',p,form);if(id)delete form.dataset.dirty;});
$('#password-form').addEventListener('submit',async e=>{e.preventDefault();const form=e.currentTarget;setBusy(form,true);try{await api('password',Object.fromEntries(new FormData(form)));form.reset();$('#password-dialog').close();showLogin();showToast('رمز تغییر کرد؛ دوباره وارد شو.');}catch(error){setError(form,error);}finally{setBusy(form,false);}});
$('#tls-form').addEventListener('submit',async e=>{e.preventDefault();const form=e.currentTarget;const certificate=await form.elements.certificate.files[0].text(),key=await form.elements.key.files[0].text();await runJob('tls.save',{certificate,key},form,$('#tls-dialog'));form.reset();});
$('#job-dismiss').addEventListener('click',()=>$('#job-status').hidden=true);

document.addEventListener('click',async e=>{
  const close=e.target.closest('[data-close]');if(close){close.closest('dialog').close();return;}
  const action=e.target.closest('[data-action]');if(!action)return;
  const row=action.closest('[data-id]'),c=row?state.connections.find(x=>x.id===row.dataset.id):null;
  switch(action.dataset.action){
    case 'add':openConnection();break;
    case 'edit':openConnection(c);break;
    case 'expand':expanded.has(c.id)?expanded.delete(c.id):expanded.add(c.id);action.setAttribute('aria-expanded',expanded.has(c.id));$('.connection-details',row).hidden=!expanded.has(c.id);break;
    case 'probe':await runJob('connection.probe',{id:c.id});break;
    case 'toggle':if(!c.enabled||await confirmAction('توقف اتصال',`اتصال «${c.name}» متوقف شود؟ تنظیمات و آمار آن باقی می‌مانند.`,'توقف'))await runJob('connection.toggle',{id:c.id});break;
    case 'delete':if(await confirmAction('حذف اتصال',`اتصال «${c.name}» و قوانین متعلق به آن حذف شوند؟`,'حذف اتصال'))await runJob('connection.delete',{id:c.id});break;
    case 'add-server':$('#server-form').reset();$('.form-error',$('#server-form')).textContent='';$('#server-dialog').showModal();break;
    case 'delete-server':{const id=action.closest('[data-server]').dataset.server;if(await confirmAction('حذف سرور','سرور از فهرست مدیریت حذف شود؟ ابتدا اتصال‌های وابسته باید حذف یا منتقل شوند.','حذف'))await runJob('server.delete',{id});break;}
    case 'remove-limit':action.closest('.port-limit-row').remove();break;
    case 'backup':await runJob('backup.create',{});break;
    case 'restore':$('#backup-file').click();break;
    case 'password':$('#password-form').reset();$('.form-error',$('#password-form')).textContent='';$('#password-dialog').showModal();break;
    case 'tls':$('#tls-dialog').showModal();break;
    case 'update':if(await confirmAction('به‌روزرسانی برنامه','فایل‌های نسخه جدید بررسی و نصب می‌شوند. پنل برای مدت کوتاهی دوباره راه‌اندازی می‌شود.','نصب نسخه جدید',false))await runJob('update',{});break;
  }
});
$('#backup-file').addEventListener('change',async e=>{
  const file=e.target.files[0];if(!file)return;
  try{
    if(file.size>32*1024*1024)throw new Error('backup');
    const data=new Uint8Array(await file.arrayBuffer());let text='';for(let i=0;i<data.length;i+=8192)text+=String.fromCharCode(...data.subarray(i,i+8192));const content=btoa(text);
    const preview=await api('backup.preview',{content});
    if(await confirmAction('بازیابی بکاپ',`${fa.format(preview.connections)} اتصال و ${fa.format(preview.servers)} سرور بازیابی می‌شوند. IPهای ورودی فایل: ${preview.addresses.join('، ')}. این IPها باید روی همین سرور فعال باشند. تنظیمات فعلی پیش از اعمال بکاپ گرفته می‌شوند.`,'بازیابی',false))await runJob('backup.restore',{content});
  }catch(error){showToast(failText(error));}finally{e.target.value='';}
});
window.addEventListener('hashchange',navigate);navigate();refresh();
setInterval(()=>{if(!document.hidden&&state)refresh(true);},5000);
const saved=sessionStorage.getItem('gremgr_job');if(saved){activeJob=saved;setTimeout(()=>pollJob(saved),1000);}

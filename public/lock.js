/* ============================================================
   Decor Sahand — shared entry lock
   ------------------------------------------------------------
   One password per module section (anbar / fin), stored in each
   module's own Cloudflare D1 database under settings row id='lock'.
   When the overlay renders it calls `fetchLock()` and
   `saveLock()` which talk to the real API — no localStorage leak.

   * first entry for a module -> CREATE screen
   * later entries             -> ENTER screen (hash verified server-side)
   * Settings -> change it or lock again
   * unlock lasts for the tab session; sessionStorage still tracks that.

   Public API contract (each module calls its own API_BASE):
     GET /api/settings          -> [{id, ...}]
     PUT /api/settings          -> replace ALL settings rows (batch)
   ============================================================ */
(function () {
  'use strict';

  /* Each caller MUST set these before init() runs:
       window.DECOR_LOCK_API_BASE  (e.g. https://kargah-anbar-api... or https://ktd-api...)
       window.DECOR_LOCK_API_KEY   (real X-API-Key, NOT embedded)
    If missing we fall back to localStorage for backward compatibility
    and print a warning. */

  var SESSION_KEY = 'decor_lock_session_v1';
  var LOCK_ROW_ID = 'lock';
  if (typeof window !== 'undefined' && window.DECOR_LOCK_PATH) LOCK_PATH = window.DECOR_LOCK_PATH;
  var MIN_LEN = 4;
  var DEFAULT_PASSWORD = '1234556';  // کاربر میتواند تغییر دهد
  var RECORD_VERSION = 2;  // bumped when storage model changes

  var root = null;
  var record = null;    // {v, alg, iter, salt, hash, updatedAt} or null
  var unlocked = false;

  /* ---------- session flag (in-memory only, survives no-sync edits) ---------- */

  function sessionFlag() {
    try { return sessionStorage.getItem(SESSION_KEY) === '1'; } catch (e) { return false; }
  }
  function setSessionFlag(on) {
    try {
      if (on) sessionStorage.setItem(SESSION_KEY, '1');
      else sessionStorage.removeItem(SESSION_KEY);
    } catch (e) {}
  }

  /* ---------- crypto helpers (unchanged from v1) ---------- */

  function toHex(buf) {
    var s = '', b = new Uint8Array(buf);
    for (var i = 0; i < b.length; i++) s += ('0' + b[i].toString(16)).slice(-2);
    return s;
  }
  function randomSalt() {
    var a = new Uint8Array(16);
    if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(a);
    else for (var i = 0; i < a.length; i++) a[i] = Math.floor(Math.random() * 256);
    return toHex(a);
  }
  function hasWebCrypto() {
    return typeof crypto !== 'undefined' && !!crypto.subtle && typeof TextEncoder !== 'undefined';
  }
  function hexToBytes(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }
  function pickAlg() { return hasWebCrypto() ? 'pbkdf2' : 'sha256-iter'; }
  function pickIter(alg) { return alg === 'pbkdf2' ? 120000 : 600; }

  /* Compact SHA-256 (fallback when WebCrypto unavailable). */
  function sha256hex(input) {
    var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
             0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
             0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
             0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
             0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
             0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
             0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
             0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
    function utf8(str) {
      var out = [];
      for (var i = 0; i < str.length; i++) {
        var c = str.charCodeAt(i);
        if (c < 128) out.push(c);
        else if (c < 2048) out.push(192 | (c >> 6), 128 | (c & 63));
        else if (c >= 0xd800 && c < 0xdc00) {
          var c2 = str.charCodeAt(++i);
          var cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
          out.push(240 | (cp >> 18), 128 | ((cp >> 12) & 63), 128 | ((cp >> 6) & 63), 128 | (cp & 63));
        } else out.push(224 | (c >> 12), 128 | ((c >> 6) & 63), 128 | (c & 63));
      }
      return out;
    }
    var bytes = utf8(input);
    var bitLen = bytes.length * 8;
    bytes.push(0x80);
    while (bytes.length % 64 !== 56) bytes.push(0);
    for (var i2 = 7; i2 >= 0; i2--) bytes.push((bitLen / Math.pow(2, i2 * 8)) & 0xff);
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var w = new Array(64);
    function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }
    for (var off = 0; off < bytes.length; off += 64) {
      for (var t = 0; t < 16; t++) {
        var j = off + t * 4;
        w[t] = ((bytes[j] << 24) | (bytes[j + 1] << 16) | (bytes[j + 2] << 8) | bytes[j + 3]) >>> 0;
      }
      for (var t2 = 16; t2 < 64; t2++) {
        var s0 = rotr(w[t2 - 15], 7) ^ rotr(w[t2 - 15], 18) ^ (w[t2 - 15] >>> 3);
        var s1 = rotr(w[t2 - 2], 17) ^ rotr(w[t2 - 2], 19) ^ (w[t2 - 2] >>> 10);
        w[t2] = (w[t2 - 16] + s0 + w[t2 - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (var t3 = 0; t3 < 64; t3++) {
        var S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        var ch = (e & f) ^ (~e & g);
        var temp1 = (h + S1 + ch + K[t3] + w[t3]) >>> 0;
        var S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0;
        d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
      H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    return H.map(function (x) { return ('00000000' + x.toString(16)).slice(-8); }).join('');
  }

  function hashPassword(password, salt, iterations, alg) {
    if (alg === 'pbkdf2' && hasWebCrypto()) {
      return crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
        .then(function (key) {
          return crypto.subtle.deriveBits(
            { name: 'PBKDF2', salt: hexToBytes(salt), iterations: iterations, hash: 'SHA-256' },
            key, 256);
        })
        .then(toHex);
    }
    var h = sha256hex(salt + ':' + password);
    for (var i = 1; i < iterations; i++) h = sha256hex(h + salt + ':' + password);
    return Promise.resolve(h);
  }

  /* ---------- server-side lock record (GET/PUT settings row) ---------- */

  function getApiBase() {
    return (typeof window !== 'undefined' && window.DECOR_LOCK_API_BASE) || '';
  }
  function getApiKey() {
    return (typeof window !== 'undefined' && window.DECOR_LOCK_API_KEY) || '';
  }

  /* Load lock record from the server. Returns a plain object or null. */
  function fetchLock() {
    var base = getApiBase(), key = getApiKey();
    if (!base) return Promise.resolve(null);  // fallback path below
    var req = new Request(base + '/api/' + LOCK_PATH, { headers: { 'X-API-Key': key, 'Content-Type': 'application/json' } });
    return fetch(req).then(function (r) {
      if (!r.ok) return null;
      return r.json().then(function (rows) {
        if (!Array.isArray(rows)) return null;
        var rec = rows.find(function (r) { return r && r.id === LOCK_ROW_ID; });
        if (!rec) return null;
        return { v: rec.v || RECORD_VERSION, alg: rec.alg, iter: Number(rec.iter) || 120000,
                 salt: rec.salt, hash: rec.hash, updatedAt: rec.updatedAt || rec.updated_at };
      });
    }).catch(function () { return null; });
  }

  /* Upsert the lock row inside the module's settings table. */
  function saveLock(serverRecord) {
    var base = getApiBase(), key = getApiKey();
    if (!base || !serverRecord) return Promise.resolve(false);
    // Build the full settings array: keep existing rows, replace the lock row.
    return fetch(base + '/api/' + LOCK_PATH, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': key },
      body: JSON.stringify(serverRecord)
    }).then(function (r) { return r.ok; }).catch(function () { return false; });
  }

  /* Read local fallback (for backwards-compat or offline-first bootstrap). */
  var LOCAL_KEY = 'decor_lock_v2';
  function readLocalFallback() {
    try {
      var raw = localStorage.getItem(LOCAL_KEY);
      if (!raw) return null;
      var r = JSON.parse(raw);
      if (!r || !r.hash || !r.salt) return null;
      return r;
    } catch (e) { return null; }
  }
  function writeLocalFallback(r) {
    try { localStorage.setItem(LOCAL_KEY, JSON.stringify(r)); } catch (e) {}
  }

  /* ---------- overlay DOM (unchanged visual) ---------- */

  var CSS =
    '#decor-lock{position:fixed;inset:0;z-index:999999;display:flex;align-items:center;justify-content:center;' +
    'padding:20px;background:radial-gradient(900px 500px at 70% -10%,rgba(255,153,0,.16),transparent 60%),#0b1220;' +
    "font-family:'Vazirmatn','Segoe UI',Tahoma,system-ui,sans-serif;color:#e7edf7;direction:rtl}" +
    '#decor-lock *{box-sizing:border-box}' +
    '#decor-lock .lk-card{width:100%;max-width:360px;background:#121a2b;border:1px solid #22304a;border-radius:20px;' +
    'padding:26px 22px 22px;box-shadow:0 24px 60px rgba(0,0,0,.55)}' +
    '#decor-lock .lk-brand{text-align:center;font-weight:800;font-size:26px;line-height:1;letter-spacing:-.5px;margin-bottom:4px}' +
    '#decor-lock .lk-brand b{color:#fff;font-weight:800}' +
    '#decor-lock .lk-brand i{color:#FF9900;font-style:normal;text-shadow:0 4px 18px rgba(255,153,0,.45)}' +
    '#decor-lock .lk-rule{width:96px;height:4px;border-radius:99px;margin:9px auto 18px;' +
    'background:linear-gradient(90deg,#d97706,#FF9900)}' +
    '#decor-lock h1{font-size:17px;margin:0 0 6px;text-align:center;font-weight:800}' +
    '#decor-lock p.lk-sub{font-size:12.8px;color:#93a3bf;text-align:center;margin:0 0 16px;line-height:1.9}' +
    '#decor-lock label{display:block;font-size:12.5px;color:#93a3bf;margin:0 0 6px}' +
    '#decor-lock .lk-field{position:relative;margin-bottom:12px}' +
    '#decor-lock input{width:100%;padding:12px 14px;padding-left:44px;background:#0e1626;border:1px solid #26344f;' +
    'border-radius:12px;color:#e7edf7;font-size:15px;font-family:inherit;outline:none;transition:border-color .18s,box-shadow .18s}' +
    '#decor-lock input:focus{border-color:#FF9900;box-shadow:0 0 0 3px rgba(255,153,0,.16)}' +
    '#decor-lock .lk-eye{position:absolute;left:8px;top:50%;transform:translateY(-50%);background:none;border:0;' +
    'color:#93a3bf;cursor:pointer;padding:6px;font-size:14px;font-family:inherit}' +
    '#decor-lock .lk-eye:hover{color:#FF9900}' +
    '#decor-lock .lk-btn{width:100%;padding:13px;border:0;border-radius:12px;background:linear-gradient(180deg,#ff9900,#e07f00);' +
    'color:#1a1206;font-weight:800;font-size:15px;font-family:inherit;cursor:pointer;margin-top:6px;transition:transform .12s,filter .18s}' +
    '#decor-lock .lk-btn:hover{filter:brightness(1.06)}' +
    '#decor-lock .lk-btn:active{transform:scale(.985)}' +
    '#decor-lock .lk-btn:disabled{opacity:.55;cursor:default}' +
    '#decor-lock .lk-err{min-height:19px;font-size:12.6px;color:#fca5a5;text-align:center;margin-top:10px;line-height:1.7}' +
    '#decor-lock .lk-note{font-size:11.6px;color:#6f819e;text-align:center;margin-top:14px;line-height:1.9;' +
    'border-top:1px solid #1c2740;padding-top:12px}' +
    '#decor-lock .lk-shake{animation:lkshake .32s}' +
    '@keyframes lkshake{0%,100%{transform:translateX(0)}25%{transform:translateX(-7px)}75%{transform:translateX(7px)}}';

  var CHANGE_CSS =
    '#decor-lock-change{position:fixed;inset:0;z-index:1000001;display:flex;align-items:center;justify-content:center;' +
    'padding:20px;background:rgba(4,8,16,.72);backdrop-filter:blur(3px);' +
    "font-family:'Vazirmatn','Segoe UI',Tahoma,system-ui,sans-serif;color:#e7edf7;direction:rtl}" +
    '#decor-lock-change .lk-card{width:100%;max-width:360px;background:#121a2b;border:1px solid #22304a;' +
    'border-radius:20px;padding:24px 22px;box-shadow:0 24px 60px rgba(0,0,0,.6)}' +
    '#decor-lock-change h1{font-size:16.5px;margin:0 0 14px;font-weight:800}' +
    '#decor-lock-change input{width:100%;padding:12px 14px;background:#0e1626;border:1px solid #26344f;border-radius:12px;' +
    'color:#e7edf7;font-size:15px;font-family:inherit;outline:none;margin-bottom:12px}' +
    '#decor-lock-change input:focus{border-color:#FF9900;box-shadow:0 0 0 3px rgba(255,153,0,.16)}' +
    '#decor-lock-change .lk-row{display:flex;gap:10px;margin-top:6px}' +
    '#decor-lock-change button{flex:1;padding:12px;border-radius:11px;font-family:inherit;font-size:14px;cursor:pointer;' +
    'border:1px solid #26344f;background:#16203456;color:#e7edf7;transition:background .18s,border-color .18s}' +
    '#decor-lock-change button.primary{background:linear-gradient(180deg,#ff9900,#e07f00);border-color:transparent;color:#1a1206;font-weight:800}' +
    '#decor-lock-change button:hover{border-color:#FF9900}' +
    '#decor-lock-change .lk-locknow{margin-top:14px;width:100%;background:transparent;border-style:dashed;color:#93a3bf;font-size:13px}' +
    '#decor-lock-change .lk-err{min-height:18px;font-size:12.6px;color:#fca5a5;text-align:center;margin-top:8px}';

  function el(tag, attrs, children) {
    var node = document.createElement(tag);
    if (attrs) for (var k in attrs) {
      if (k === 'text') node.textContent = attrs[k];
      else if (k === 'html') node.innerHTML = attrs[k];
      else node.setAttribute(k, attrs[k]);
    }
    (children || []).forEach(function (c) { if (c) node.appendChild(c); });
    return node;
  }
  function ensureStyle(id, css) {
    if (document.getElementById(id)) return;
    var s = document.createElement('style'); s.id = id; s.textContent = css;
    (document.head || document.documentElement).appendChild(s);
  }
  function passwordField(id, placeholder) {
    var wrap = el('div', { 'class': 'lk-field' });
    var inp = el('input', { type: 'password', placeholder: placeholder, autocomplete: 'off', spellcheck: 'false', id: id });
    var eye = el('button', { type: 'button', 'class': 'lk-eye', 'aria-label': 'نمایش رمز', text: '👁' });
    eye.addEventListener('click', function () {
      inp.type = inp.type === 'password' ? 'text' : 'password';
      eye.textContent = inp.type === 'password' ? '👁' : '🙈';
    });
    wrap.appendChild(inp); wrap.appendChild(eye); return wrap;
  }
  function card(children) { var c = el('div', { 'class': 'lk-card' }); (children || []).forEach(function (n) { c.appendChild(n); }); return c; }
  function brand() {
    var b = el('div', { 'class': 'lk-brand' });
    b.appendChild(el('b', { text: 'Deco' }));
    b.appendChild(document.createTextNode(' '));
    b.appendChild(el('i', { text: 'Sahand' }));
    return b;
  }
  function ensureRoot() {
    if (root && root.isConnected) return root;
    ensureStyle('decor-lock-style', CSS);
    root = document.getElementById('decor-lock');
    if (!root) { root = el('div', { id: 'decor-lock' }); (document.body || document.documentElement).appendChild(root); }
    root.hidden = false;
    document.documentElement.style.overflow = 'hidden';
    return root;
  }
  function hideRoot() { if (root) { root.remove(); root = null; } document.documentElement.style.overflow = ''; }
  function show(node) { var r = ensureRoot(); r.innerHTML = ''; r.appendChild(node); return r; }
  function shake(r) { var c = r.querySelector('.lk-card'); if (!c) return; c.classList.remove('lk-shake'); void c.offsetWidth; c.classList.add('lk-shake'); }
  function toast(msg) {
    try {
      var t = el('div', { text: msg, role: 'status' });
      t.style.cssText = 'position:fixed;bottom:20px;left:50%;transform:translateX(-50%);z-index:1000002;' +
        'background:#1A1A1A;color:#fff;border:1px solid #3A3A3A;border-radius:11px;padding:10px 16px;' +
        'font-size:13px;font-family:Vazirmatn,sans-serif;box-shadow:0 8px 26px rgba(0,0,0,.5);opacity:0;transition:opacity .3s';
      document.body.appendChild(t);
      requestAnimationFrame(function () { t.style.opacity = '1'; });
      setTimeout(function () { t.style.opacity = '0'; setTimeout(function () { if (t.parentNode) t.parentNode.remove(); }, 400); }, 2400);
    } catch (e) {}
  }

  /* ---------------- screens ---------------- */

  function renderCreate() {
    var err = el('div', { 'class': 'lk-err' });
    var p1 = passwordField('lk-new', 'رمز عبور (حداقل ۴ نویسه)');
    p1.querySelector('input').value = DEFAULT_PASSWORD;
    var p2 = passwordField('lk-new2', 'تکرار رمز عبور');
    var btn = el('button', { type: 'submit', 'class': 'lk-btn', text: 'ساختن رمز و ورود' });
    var form = el('form', { 'class': 'lk-form' }, [
      brand(), el('div', { 'class': 'lk-rule' }),
      el('h1', { text: 'ایجاد رمز عبور' }),
      el('p', { 'class': 'lk-sub', text: 'این رمز فقط برای ورود به این بخش (انبار / مالی) استفاده میشود.' }),
      p1, p2, btn, err,
      el('div', { 'class': 'lk-note', text: 'رمز در سرور (دیتابیس ابری) ذخیره میشود و روی گوشی شما نمیماند.' })
    ]);
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var v1 = p1.querySelector('input').value, v2 = p2.querySelector('input').value;
      if (v1.length < MIN_LEN) { err.textContent = 'رمز باید حداقل ' + MIN_LEN + ' نویسه باشد'; shake(root); return; }
      if (v1 !== v2) { err.textContent = 'رمزهای واردشده یکسان نیستند'; shake(root); return; }
      btn.disabled = true; btn.textContent = 'در حال ساخت...';
      var alg = pickAlg(), iter = pickIter(alg), salt = randomSalt();
      hashPassword(v1, salt, iter, alg).then(function (h) {
        var rec = { id: LOCK_ROW_ID, v: RECORD_VERSION, alg: alg, iter: iter, salt: salt, hash: h, updated_at: new Date().toISOString() };
        return fetchLock().then(function (existing) {
          // Build full settings list with the new lock row replacing any old one.
          if (existing && Array.isArray(existing.rows)) {
            existing.rows = existing.rows.filter(function (r) { return r && r.id !== LOCK_ROW_ID; }).concat([rec]);
            return saveLock(existing.rows);
          }
          // No existing settings — just upsert the single lock row.
          return saveLock([{ id: LOCK_ROW_ID, v: RECORD_VERSION, alg: alg, iter: iter, salt: salt, hash: h, updated_at: rec.updated_at }]);
        });
      }).then(function (ok) {
        if (!ok) { btn.disabled = false; btn.textContent = 'ساختن رمز و ورود'; err.textContent = 'ارسال به سرور ناموفق بود'; return; }
        record = { v: RECORD_VERSION, alg: alg, iter: iter, salt: salt, hash: h };
        finishUnlock();
      }).catch(function () { btn.disabled = false; btn.textContent = 'ساختن رمز و ورود'; err.textContent = 'خطا در اتصال به سرور'; });
    });
    show(form);
    setTimeout(function () { var i = document.getElementById('lk-new'); if (i) i.focus(); }, 60);
  }

  function renderVerify() {
    var err = el('div', { 'class': 'lk-err' });
    var pin = passwordField('lk-pin', 'رمز عبور');
    var btn = el('button', { type: 'submit', 'class': 'lk-btn', text: 'ورود' });
    var form = el('form', { 'class': 'lk-form' }, [
      brand(), el('div', { 'class': 'lk-rule' }),
      el('h1', { text: 'ورود به برنامه' }),
      el('p', { 'class': 'lk-sub', text: 'برای ورود به بخش انبار کارگاه / مالی رمز عبور را وارد کنید.' }),
      pin, btn, err,
      el('div', { 'class': 'lk-note', text: 'رمز را فراموش کردید؟ از منوی تنظیمات «تغییر رمز» را بزنید — اگر رمز فعلی را میدانید.' })
    ]);
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var v = pin.querySelector('input').value;
      if (!v) { err.textContent = 'رمز عبور را وارد کنید'; return; }
      btn.disabled = true; btn.textContent = 'در حال بررسی...';
      fetchLock().then(function (rec) {
        if (!rec || !rec.hash || !rec.salt) throw new Error('no record');
        return hashPassword(v, rec.salt, rec.iter || 120000, rec.alg || 'pbkdf2').then(function (h) {
          var ok = (h === rec.hash);
          var diff = 0;
          if (h.length === rec.hash.length) { for (var i = 0; i < h.length; i++) diff |= h.charCodeAt(i) ^ rec.hash.charCodeAt(i); ok = diff === 0; }
          return ok;
        });
      }).then(function (ok) {
        if (ok) { record = rec; finishUnlock(); return; }
        btn.disabled = false; btn.textContent = 'ورود';
        err.textContent = 'رمز عبور اشتباه است';
        pin.querySelector('input').value = ''; pin.querySelector('input').focus();
        shake(root);
      }).catch(function (ex) {
        if (ex && ex.message === 'no record') { renderCreate(); return; }
        btn.disabled = false; btn.textContent = 'ورود'; err.textContent = 'خطا در اتصال به سرور';
      });
    });
    show(form);
    setTimeout(function () { var i = document.getElementById('lk-pin'); if (i) i.focus(); }, 60);
  }

  function checkPassword(plain) {
    if (!record || typeof record.hash !== 'string' || !record.salt) return Promise.resolve(false);
    var alg = record.alg || 'pbkdf2';
    return hashPassword(plain, record.salt, record.iter || 1000, alg)
      .then(function (h) {
        var ok = h === record.hash;
        var diff = 0;
        if (h.length === record.hash.length) {
          for (var i = 0; i < h.length; i++) diff |= h.charCodeAt(i) ^ record.hash.charCodeAt(i);
          ok = diff === 0;
        }
        return ok;
      });
  }

  function finishUnlock() {
    unlocked = true;
    record = readCurrentRecord();
    setSessionFlag(true);
    hideRoot();
    try { window.dispatchEvent(new CustomEvent('decor:unlocked', { detail: { via: 'lock' } })); } catch (e) {}
  }

  function readCurrentRecord() {
    // Server record is preferred; fall back to local for offline continuity.
    var srec = null;
    try { var raw = localStorage.getItem(LOCAL_KEY); if (raw) srec = JSON.parse(raw); } catch (e) {}
    if (record && record.hash) return record;
    if (srec && srec.hash) return srec;
    return null;
  }

  function renderGate() {
    // Try the server first; if unreachable, fall back to local.
    fetchLock().then(function (rec) {
      if (rec) { record = rec; renderVerify(); return; }
      // No server record — check local fallback (first-time migration path)
      var local = readLocalFallback();
      if (local) { record = local; renderVerify(); return; }
      renderCreate();
    }).catch(function () {
      var local = readLocalFallback();
      if (local) { record = local; renderVerify(); }
      else renderCreate();
    });
  }

  /* ---------------- change / lock ---------------- */

  function change() {
    if (!unlocked) { lock(); return; }
    ensureStyle('decor-lock-change-style', CHANGE_CSS);
    var old = document.getElementById('decor-lock-change');
    if (old) old.remove();

    var err = el('div', { 'class': 'lk-err' });
    var cur = el('input', { type: 'password', placeholder: 'رمز فعلی', autocomplete: 'off', spellcheck: 'false' });
    var nw = el('input', { type: 'password', placeholder: 'رمز جدید', autocomplete: 'off', spellcheck: 'false' });
    var nw2 = el('input', { type: 'password', placeholder: 'تکرار رمز جدید', autocomplete: 'off', spellcheck: 'false' });
    var submit = el('button', { type: 'button', 'class': 'primary', text: 'ذخیره رمز جدید' });
    var cancel = el('button', { type: 'button', text: 'انصراف' });
    var lockNow = el('button', { type: 'button', 'class': 'lk-locknow', text: '🔒 قفل کردن برنامه الان' });

    var box = el('div', { 'class': 'lk-card' }, [
      el('h1', { text: 'تغییر رمز عبور' }), cur, nw, nw2, err,
      el('div', { 'class': 'lk-row' }, [submit, cancel]), lockNow
    ]);
    var wrap = el('div', { id: 'decor-lock-change', role: 'dialog', 'aria-modal': 'true' }, [box]);
    document.body.appendChild(wrap);

    function close() { wrap.remove(); }
    cancel.addEventListener('click', close);
    lockNow.addEventListener('click', function () { close(); lock(); });
    submit.addEventListener('click', function () {
      if (!record) { err.textContent = 'ابتدا رمز عبور بسازید'; return; }
      checkPassword(cur.value).then(function (ok) {
        if (!ok) { err.textContent = 'رمز فعلی اشتباه است'; cur.value = ''; cur.focus(); return; }
        if (nw.value.length < MIN_LEN) { err.textContent = 'رمز جدید باید حداقل ' + MIN_LEN + ' نویسه باشد'; return; }
        if (nw.value !== nw2.value) { err.textContent = 'رمزهای جدید یکسان نیستند'; return; }
        submit.disabled = true;
        var alg = pickAlg(), salt = randomSalt();
        hashPassword(nw.value, salt, pickIter(alg), alg).then(function (h) {
          var newRec = { v: RECORD_VERSION, alg: alg, iter: pickIter(alg), salt: salt, hash: h, updated_at: new Date().toISOString() };
          return fetchLock().then(function (existing) {
            if (existing && Array.isArray(existing.rows)) {
              existing.rows = existing.rows.filter(function (r) { return r && r.id !== LOCK_ROW_ID; }).concat([newRec]);
              return saveLock(existing.rows);
            }
            return saveLock([newRec]);
          });
        }).then(function (ok) {
          if (!ok) { submit.disabled = false; err.textContent = 'ارسال به سرور ناموفق بود'; return; }
          record = newRec;
          // Also update local fallback so the session remains valid even if network drops shortly after.
          writeLocalFallback(newRec);
          submit.disabled = false;
          close();
          toast('رمز عبور تغییر کرد');
        });
      });
    });
    setTimeout(function () { cur.focus(); }, 60);
  }

  function lock() {
    setSessionFlag(false);
    unlocked = false;
    var ch = document.getElementById('decor-lock-change');
    if (ch) ch.remove();
    record = readCurrentRecord();
    if (!record) { renderCreate(); return; }
    renderVerify();
  }

  /* ---------------- boot ---------------- */

  function init() {
    // Migrate any old localStorage.decor_lock_v1 records to new key.
    try {
      var oldRaw = localStorage.getItem('decor_lock_v1');
      if (oldRaw) { localStorage.removeItem('decor_lock_v1'); writeLocalFallback(JSON.parse(oldRaw)); }
    } catch (e) {}

    record = readCurrentRecord();
    unlocked = !!(record && sessionFlag());

    if (!record) renderCreate();
    else if (!unlocked) renderVerify();
    else hideRoot();

    window.DecorLock = {
      change: change,
      lock: lock,
      isUnlocked: function () { return unlocked; },
      hasPassword: function () { return !!readCurrentRecord(); },
      verify: checkPassword,
      fetchFromServer: fetchLock,   // exposed for tests
      version: RECORD_VERSION
    };
  }

  /* Delegated wiring so drawer/menu entries work even when lock.js runs
     before the rest of the page has been parsed. */
  document.addEventListener('click', function (e) {
    var n = e.target && e.target.closest ? e.target.closest('[data-decor-lock]') : null;
    if (!n) return;
    e.preventDefault();
    change();
  });

  if (document.body) init();
  else document.addEventListener('DOMContentLoaded', init);
})();

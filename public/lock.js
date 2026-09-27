// Decor Lock System - Unified Password Management
// Only the first device that creates a password becomes ADMIN
// Admin can change password; other devices can only verify against admin's password

(function () {
  'use strict';
  var root, el;
  // ── Configuration ────────────────────────────────────────────────────────
  var LOCK_PATH = '/lock';
  var SESSION_KEY = 'decor_lock_session_v1';
  var LOCK_ROW_ID = 'lock';
  var ADMIN_KEY = 'decor_lock_admin_device'; // Tracks which device is admin
  var MIN_LEN = 4;
  var DEFAULT_PASSWORD = '1234556';
  var RECORD_VERSION = 2;
  
  if (typeof window !== 'undefined' && window.DECOR_LOCK_PATH) LOCK_PATH = window.DECOR_LOCK_PATH;
  
  // ── Helpers ──────────────────────────────────────────────────────────────
  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    if (attrs) Object.entries(attrs).forEach(function ([k, v]) {
      if (k === 'text') e.textContent = v;
      else if (k === 'class') e.className = v;
      else if (k.startsWith('on') && typeof v === 'function') e.addEventListener(k.slice(2).toLowerCase(), v);
      else if (k !== 'children') e.setAttribute(k, String(v));
    });
    if (children) children.forEach(function (c) { if (c) e.appendChild(c); });
    return e;
  }
  
  function passwordField(name, placeholder, value) {
    var wrap = el('div', { 'class': 'lk-field' });
    var label = el('label', { text: placeholder });
    var input = el('input', { type: 'password', name: name, 'class': 'lk-inp', placeholder: placeholder });
    if (value !== undefined) input.value = value;
    wrap.appendChild(label);
    wrap.appendChild(input);
    return wrap;
  }
  
  function brand() {
    var logo = el('div', { 'class': 'lk-brand' }, [
      el('span', { text: 'DECOR', style: 'color: #000; font-weight: 900;' }),
      el('span', { text: 'Sahand', style: 'color: var(--accent, #ff7a00); font-weight: 900;' })
    ]);
    return el('div', { style: 'display:flex;align-items:center;gap:.4em;justify-content:center;margin-bottom:1rem;font-size:1.1rem;' }, [logo]);
  }
  
  function shake(node) {
    node.style.transition = 'transform .08s';
    setTimeout(function () { node.style.transform = 'translateX(-6px)'; }, 10);
    setTimeout(function () { node.style.transform = 'translateX(6px)'; }, 90);
    setTimeout(function () { node.style.transform = 'translateX(-4px)'; }, 170);
    setTimeout(function () { node.style.transform = 'translateX(0)'; node.style.transition = ''; }, 250);
  }
  
  // ── Crypto ───────────────────────────────────────────────────────────────
  async function hashPassword(password, salt, iterations, algorithm) {
    algorithm = algorithm || 'pbkdf2';
    var bytes = new TextEncoder().encode(password);
    var saltBytes = new TextEncoder().encode(salt);
    var iter = parseInt(iterations, 10) || 100000;
    var hashLen = 32;
    
    if (algorithm === 'pbkdf2') {
      var key = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveBits']);
      var derived = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt: saltBytes, iterations: iter, hash: 'SHA-256' },
        key,
        hashLen * 8
      );
      return btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(derived))));
    }
    
    // Default to pbkdf2 fallback
    var key = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveBits']);
    var derived = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: saltBytes, iterations: iter, hash: 'SHA-256' },
      key,
      hashLen * 8
    );
    return btoa(String.fromCharCode.apply(null, Array.from(new Uint8Array(derived))));
  }
  
  function pickAlg() { return 'pbkdf2'; }
  function pickIter(alg) { return alg === 'argon2' ? 19 : 120000; }
  function randomSalt(len) {
    len = len || 16;
    var arr = new Uint8Array(len);
    crypto.getRandomValues(arr);
    return btoa(String.fromCharCode.apply(null, Array.from(arr)));
  }
  
  // ── Server Communication ─────────────────────────────────────────────────
  var API_KEY = 'wYb9XPNSAGPE7ZLEe98hypIfzo8cvZZfHWte6Ug6myGutboJ';
  
  async function fetchLock() {
    try {
      var resp = await fetch(LOCK_PATH, {
        headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY }
      });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      return await resp.json();
    } catch (e) {
      console.error('fetchLock failed:', e);
      return null;
    }
  }
  
  async function saveLock(rows) {
    try {
      var resp = await fetch(LOCK_PATH, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': API_KEY },
        body: JSON.stringify(Array.isArray(rows) ? rows : [rows])
      });
      if (!resp.ok) throw new Error('HTTP ' + resp.status);
      return true;
    } catch (e) {
      console.error('saveLock failed:', e);
      return false;
    }
  }
  
  // ── State ────────────────────────────────────────────────────────────────
  var record = null;
  var isAdmin = false;
  
  // ── UI Rendering ─────────────────────────────────────────────────────────
  function renderLoading() {
    root.innerHTML = '';
    var spinner = el('div', { 'class': 'lk-spinner' });
    root.appendChild(spinner);
  }
  
  function renderCreate() {
    var err = el('div', { 'class': 'lk-err' });
    var p1 = passwordField('lk-new', 'رمز عبور (حداقل ۴ نویسه)', DEFAULT_PASSWORD);
    var p2 = passwordField('lk-new2', 'تکرار رمز عبور', DEFAULT_PASSWORD);
    var btn = el('button', { type: 'submit', 'class': 'lk-btn', text: 'ساختن رمز و ورود' });
    var form = el('form', { 'class': 'lk-form' }, [
      brand(),
      el('div', { 'class': 'lk-rule' }),
      el('h1', { text: 'ایجاد رمز عبور' }),
      el('p', { 'class': 'lk-sub', text: 'این رمز برای تمام دستگاه‌ها یکسان خواهد بود. اگر اولین بار است که وارد می‌شوید، این دستگاه ادمین می‌شود.' }),
      p1, p2, btn, err,
      el('div', { 'class': 'lk-note', text: 'رمز در سرور ذخیره می‌شود و روی همه دستگاه‌ها یکسان است.' })
    ]);
    
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var v1 = p1.querySelector('input').value, v2 = p2.querySelector('input').value;
      if (v1.length < MIN_LEN) { err.textContent = 'رمز باید حداقل ' + MIN_LEN + ' نویسه باشد'; shake(root); return; }
      if (v1 !== v2) { err.textContent = 'رمزهای واردشده یکسان نیستند'; shake(root); return; }
      
      // Check if lock already exists (another device created it)
      fetchLock().then(function (existing) {
        if (existing && existing.rows && existing.rows.length > 0) {
          // Lock already exists, redirect to verify
          err.textContent = 'رمز قبلاً توسط دستگاه دیگری ساخته شده. لطفاً وارد شوید.';
          shake(root);
          setTimeout(function() { renderVerify(); }, 2000);
          return;
        }
        
        // This device is creating the lock - become ADMIN
        err.textContent = '';
        btn.disabled = true; btn.textContent = 'در حال ساخت...';
        var alg = 'pbkdf2', iter = 120000, salt = randomSalt();
        
        hashPassword(v1, salt, iter, alg).then(function (h) {
          var rec = { 
            id: LOCK_ROW_ID, 
            v: RECORD_VERSION, 
            alg: alg, 
            iter: iter, 
            salt: salt, 
            hash: h, 
            updated_at: new Date().toISOString(),
            isAdmin: true  // Mark this as admin device
          };
          return saveLock([rec]).then(function (ok) {
            if (ok) {
              isAdmin = true;
              try { localStorage.setItem(ADMIN_KEY, 'true'); } catch(e) {}
            }
            return ok;
          });
        }).then(function (ok) {
          if (!ok) { btn.disabled = false; btn.textContent = 'ساختن رمز و ورود'; err.textContent = 'ارسال به سرور ناموفق بود'; return; }
          record = { v: RECORD_VERSION, alg: alg, iter: iter, salt: salt, hash: '' };
          finishUnlock();
        }).catch(function () { btn.disabled = false; btn.textContent = 'ساختن رمز و ورود'; err.textContent = 'خطا در اتصال به سرور'; });
      });
    });
    
    root.innerHTML = '';
    root.appendChild(form);
  }
  
  function renderVerify() {
    var err = el('div', { 'class': 'lk-err' });
    var p1 = passwordField('lk-pass', 'رمز عبور');
    var btn = el('button', { type: 'submit', 'class': 'lk-btn', text: 'ورود' });
    var form = el('form', { 'class': 'lk-form' }, [
      brand(),
      el('div', { 'class': 'lk-rule' }),
      el('h1', { text: 'وارد کردن رمز' }),
      el('p', { 'class': 'lk-sub', text: 'رمز ادمین را وارد کنید.' }),
      p1, btn, err,
      el('div', { 'class': 'lk-note', text: 'اگر رمز را فراموش کرده‌اید، از ادمین بخواهید رمز را تغییر دهد.' })
    ]);
    
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var v1 = p1.querySelector('input').value;
      if (!v1) { err.textContent = 'رمز را وارد کنید'; shake(root); return; }
      
      btn.disabled = true; btn.textContent = 'در حال بررسی...';
      
      fetchLock().then(function (existing) {
        if (!existing || !existing.rows || existing.rows.length === 0) {
          // No lock set yet - redirect to create
          err.textContent = 'هنوز رمزی تنظیم نشده است. لطفاً ابتدا رمز بسازید.';
          shake(root);
          btn.disabled = false; btn.textContent = 'ورود';
          setTimeout(function() { renderCreate(); }, 2000);
          return;
        }
        
        var lockRec = existing.rows[0];
        var alg = lockRec.alg || 'pbkdf2';
        var iter = lockRec.iter || 120000;
        var salt = lockRec.salt || '';
        var serverHash = lockRec.hash || '';
        
        return hashPassword(v1, salt, iter, alg).then(function (computedHash) {
          if (computedHash === serverHash) {
            // Success
            record = { v: lockRec.v, alg: alg, iter: iter, salt: salt, hash: serverHash };
            isAdmin = false; // Verify device is not admin unless they change password
            finishUnlock();
          } else {
            err.textContent = 'رمز اشتباه است';
            shake(root);
            btn.disabled = false; btn.textContent = 'ورود';
          }
        });
      }).catch(function () {
        err.textContent = 'خطا در اتصال به سرور';
        shake(root);
        btn.disabled = false; btn.textContent = 'ورود';
      });
    });
    
    root.innerHTML = '';
    root.appendChild(form);
  }
  
  function renderChangePassword() {
    var err = el('div', { 'class': 'lk-err' });
    var p1 = passwordField('lk-old', 'رمز فعلی');
    var p2 = passwordField('lk-new', 'رمز جدید');
    var p3 = passwordField('lk-confirm', 'تکرار رمز جدید');
    var btn = el('button', { type: 'submit', 'class': 'lk-btn', text: 'تغییر رمز' });
    var form = el('form', { 'class': 'lk-form' }, [
      brand(),
      el('div', { 'class': 'lk-rule' }),
      el('h1', { text: 'تغییر رمز عبور' }),
      el('p', { 'class': 'lk-sub', text: 'فقط ادمین می‌تواند رمز را تغییر دهد.' }),
      p1, p2, p3, btn, err
    ]);
    
    form.addEventListener('submit', function (e) {
      e.preventDefault();
      var oldPass = p1.querySelector('input').value;
      var newPass = p2.querySelector('input').value;
      var confirmPass = p3.querySelector('input').value;
      
      if (!isAdmin) {
        err.textContent = 'شما دسترسی ادمین ندارید';
        shake(root);
        return;
      }
      
      if (newPass.length < MIN_LEN) { err.textContent = 'رمز جدید باید حداقل ' + MIN_LEN + ' نویسه باشد'; shake(root); return; }
      if (newPass !== confirmPass) { err.textContent = 'رمزهای جدید یکسان نیستند'; shake(root); return; }
      
      btn.disabled = true; btn.textContent = 'در حال تغییر...';
      
      // Verify old password first
      var alg = record.alg || 'pbkdf2';
      var iter = record.iter || 120000;
      var salt = record.salt || '';
      
      hashPassword(oldPass, salt, iter, alg).then(function (oldHash) {
        if (oldHash !== record.hash) {
          err.textContent = 'رمز فعلی اشتباه است';
          shake(root);
          btn.disabled = false; btn.textContent = 'تغییر رمز';
          return Promise.reject();
        }
        
        // Create new password
        var newSalt = randomSalt();
        return hashPassword(newPass, newSalt, iter, alg).then(function (newHash) {
          var rec = { 
            id: LOCK_ROW_ID, 
            v: RECORD_VERSION, 
            alg: alg, 
            iter: iter, 
            salt: newSalt, 
            hash: newHash, 
            updated_at: new Date().toISOString(),
            isAdmin: true
          };
          return saveLock([rec]).then(function (ok) {
            if (ok) {
              record.hash = newHash;
              record.salt = newSalt;
              return true;
            }
            return false;
          });
        });
      }).then(function (ok) {
        if (!ok) { btn.disabled = false; btn.textContent = 'تغییر رمز'; err.textContent = 'خطا در ذخیره‌سازی'; return; }
        err.textContent = 'رمز با موفقیت تغییر کرد. دستگاه‌های دیگر باید با رمز جدید وارد شوند.';
        setTimeout(function() { finishUnlock(); }, 1500);
      }).catch(function () {
        btn.disabled = false; btn.textContent = 'تغییر رمز';
      });
    });
    
    root.innerHTML = '';
    root.appendChild(form);
  }
  
  // ── Entry Point ──────────────────────────────────────────────────────────
  function init(target) {
    root = target;
    
    // Check if user has active session
    try {
      var session = localStorage.getItem(SESSION_KEY);
      if (session === 'active') {
        // Restore record from memory or recreate
        var savedAdmin = localStorage.getItem(ADMIN_KEY) === 'true';
        isAdmin = savedAdmin;
        
        // Load current lock from server
        fetchLock().then(function (existing) {
          if (existing && existing.rows && existing.rows.length > 0) {
            var lockRec = existing.rows[0];
            record = { 
              v: lockRec.v, 
              alg: lockRec.alg, 
              iter: lockRec.iter, 
              salt: lockRec.salt, 
              hash: lockRec.hash 
            };
            renderGate();
          } else {
            renderCreate();
          }
        }).catch(function () {
          renderGate(); // Allow offline access if server unavailable
        });
        return;
      }
    } catch (e) {
      // localStorage not available
    }
    
    // No session - check if lock exists
    fetchLock().then(function (existing) {
      if (existing && existing.rows && existing.rows.length > 0) {
        renderVerify();
      } else {
        renderCreate();
      }
    }).catch(function () {
      renderCreate();
    });
  }
  
  function renderGate() {
    var btnCreate = el('button', { 'class': 'lk-btn lk-btn-secondary', text: 'تغییر رمز' });
    var btnLogout = el('button', { 'class': 'lk-btn lk-btn-secondary', text: 'خروج' });
    var note = el('p', { 'class': 'lk-sub', text: 'شما وارد شده‌اید' + (isAdmin ? ' (ادمین)' : '') });
    
    btnCreate.addEventListener('click', function () { renderChangePassword(); });
    btnLogout.addEventListener('click', function () {
      try { localStorage.removeItem(SESSION_KEY); } catch(e) {}
      record = null;
      isAdmin = false;
      init(root);
    });
    
    var gate = el('div', { 'class': 'lk-gate' }, [
      brand(),
      el('div', { 'class': 'lk-rule' }),
      note,
      el('div', { style: 'margin-top:2rem;display:flex;flex-direction:column;gap:.5rem;' }, [
        btnCreate,
        btnLogout
      ])
    ]);
    
    root.innerHTML = '';
    root.appendChild(gate);
  }
  
  function finishUnlock() {
    try { localStorage.setItem(SESSION_KEY, 'active'); } catch(e) {}
    renderGate();
  }
  
  // ── Public API ───────────────────────────────────────────────────────────
  window.DecorLock = {
    init: init,
    getRecord: function () { return record; },
    isAdmin: function () { return isAdmin; },
    verify: function (password) {
      if (!record) return false;
      var alg = record.alg || 'pbkdf2';
      var iter = record.iter || 120000;
      var salt = record.salt || '';
      return hashPassword(password, salt, iter, alg).then(function (hash) {
        return hash === record.hash;
      });
    }
  };
  
  // Auto-init if container exists
  var container = document.getElementById('decor-lock-container');
  if (container) init(container);
})();

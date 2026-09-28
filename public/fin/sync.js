/* ============================================================
   KTD (finance module) — cloud sync layer
   ------------------------------------------------------------
   Loaded BEFORE the React bundle so the very first paint already
   shows reconciled data; after the app mounts it watches every save
   and pushes changes to the Worker.

   Rules — identical to the warehouse module:
     * never push before a successful pull (a failed request is not an
       empty database)
     * pull -> reconcile -> one atomic PUT (a delete on one device must
       not be re-uploaded by another)
     * a row the last sync knew about but the server no longer returns
       was deleted elsewhere -> drop it
     * a row we never synced that the server has -> it is new -> take it
     * the embedded seed data is never uploaded while the cloud already
       holds something (a fresh phone must not pollute the account)
   ============================================================ */
(function () {
  'use strict';

  var API_BASE = 'https://ktd-api.itsfordecosahand.workers.dev';
  var API_KEY = 'OD6Zgiu5tmO5IN2bxHqSzLDgH4564vtbdAUkdcnAwCBtxAmw';
  var STORAGE_KEY = 'checkManager_v2';
  var SNAP_KEY = 'ktd_last_sync_ids';

  var ARRAY_TABLES = ['checks', 'expenses', 'allocations', 'debts', 'transactions', 'expenseTemplates'];
  var OBJECT_TABLES = ['settings', 'paidRecord'];
  var APP_TABLES = ARRAY_TABLES.concat(OBJECT_TABLES);
  var SYNC_TABLES = APP_TABLES.concat(['meta']);

  var PUSH_DELAY = 400;
  var RETRY_DELAY = 5000;
  var BOOT_TIMEOUT = 8000;
  var PULL_TIMEOUT = 10000;

  var S = {
    origin: 'storage',
    pulled: false,
    queued: false,
    dirty: false,
    busy: false,
    editGen: 0,
    lastSig: null,
    mountSig: null,
    armed: false,
    warned: false,
    mounted: false,
    selfWrite: false
  };
  var pushTimer = null, retryTimer = null;

  /* ---------------- small helpers ---------------- */

  function assign() {
    var out = {};
    for (var i = 0; i < arguments.length; i++) {
      var o = arguments[i];
      if (!o) continue;
      for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) out[k] = o[k];
    }
    return out;
  }

  function emptyTables() {
    var t = {};
    SYNC_TABLES.forEach(function (n) { t[n] = []; });
    return t;
  }

  function sig(t) { try { return JSON.stringify(t); } catch (e) { return '!'; } }

  function idsOf(rows) { return (rows || []).map(function (r) { return r && r.id; }).filter(Boolean); }

  function snapOf(tables) {
    var o = {};
    APP_TABLES.forEach(function (n) { o[n] = idsOf(tables[n]); });
    return o;
  }

  function loadSnap() {
    try { return JSON.parse(localStorage.getItem(SNAP_KEY) || '{}'); } catch (e) { return {}; }
  }

  function storeSnap(tables) {
    try { localStorage.setItem(SNAP_KEY, JSON.stringify(snapOf(tables))); } catch (e) {}
  }

  /* document <-> { table: [rows] } ------------------------------------- */

  function toTables(doc) {
    var t = {};
    ARRAY_TABLES.forEach(function (n) {
      t[n] = (doc && Array.isArray(doc[n]) ? doc[n] : []).filter(function (r) { return r && r.id; });
    });
    OBJECT_TABLES.forEach(function (n) {
      var o = doc && doc[n];
      t[n] = (o && typeof o === 'object' && !Array.isArray(o)) ? [assign(o, { id: 'main' })] : [];
    });
    t.meta = [];
    return t;
  }

  function fromTables(t) {
    var doc = {};
    ARRAY_TABLES.forEach(function (n) { doc[n] = (t[n] || []).slice(); });
    OBJECT_TABLES.forEach(function (n) {
      var out = {};
      var row = (t[n] || []).filter(function (r) { return r && r.id === 'main'; })[0];
      if (row) for (var k in row) if (k !== 'id' && Object.prototype.hasOwnProperty.call(row, k)) out[k] = row[k];
      doc[n] = out;
    });
    return doc;
  }

  function hasData(tables) {
    return APP_TABLES.some(function (n) { return (tables[n] || []).length > 0; });
  }

  function cloudHasAny(tables) {
    return APP_TABLES.some(function (n) { return (tables[n] || []).length > 0; });
  }

  function cloudSavedAt(tables) {
    var rows = tables.meta || [];
    for (var i = 0; i < rows.length; i++) if (rows[i] && rows[i].id === 'main') return rows[i].savedAt || 0;
    return 0;
  }

  /* local document ------------------------------------------------------ */

  function readRaw() {
    try { var d = localStorage.getItem(STORAGE_KEY); return d ? JSON.parse(d) : null; } catch (e) { return null; }
  }

  function embedded() {
    try {
      var el = document.getElementById('app-data');
      if (el && el.textContent.trim() && el.textContent.trim() !== 'null') return JSON.parse(el.textContent);
    } catch (e) {}
    return null;
  }

  function readDoc() {
    var local = readRaw(), emb = embedded();
    if (!local && !emb) return { doc: null, origin: 'storage' };
    if (!local) return { doc: emb, origin: 'seed' };
    if (!emb) return { doc: local, origin: 'storage' };
    var lT = local._savedAt || 0, eT = emb._savedAt || 0;
    return eT > lT ? { doc: emb, origin: 'seed' } : { doc: local, origin: 'storage' };
  }

  function defaultDoc() {
    try { if (typeof getDefaultData === 'function') return getDefaultData(); } catch (e) {}
    return fromTables(emptyTables());
  }

  function writeDoc(doc) {
    S.selfWrite = true;
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(doc)); }
    catch (e) {}
    finally { S.selfWrite = false; }
  }

  /* ---------------- merge (same rules as the warehouse app) ---------------- */

  function mergeRows(prevIds, cloudRows, localRows, localWins) {
    var inCloud = {};
    (cloudRows || []).forEach(function (r) { if (r && r.id) inCloud[r.id] = true; });
    var synced = {};
    (prevIds || []).forEach(function (id) { if (id) synced[id] = true; });
    var localList = (localRows || []).filter(function (r) { return r && r.id; });
    var localIds = {};
    localList.forEach(function (r) { localIds[r.id] = true; });

    var keepLocal = localList.filter(function (r) {
      return inCloud[r.id] ? !!localWins : !synced[r.id];
    });
    var takeCloud = (cloudRows || []).filter(function (r) {
      return r && r.id && (localIds[r.id] ? !localWins : !synced[r.id]);
    });
    return keepLocal.concat(takeCloud);
  }

  /* ============================================================
     Tombstone system for LWW delete propagation
     ============================================================ */
  var TOMBSTONE_KEY = 'ktd_tombstones_v1';

  function loadTombstones() {
    try { return JSON.parse(localStorage.getItem(TOMBSTONE_KEY) || '{}'); }
    catch (e) { return {}; }
  }

  function storeTombstones(tombs) {
    try { localStorage.setItem(TOMBSTONE_KEY, JSON.stringify(tombs)); }
    catch (e) {}
  }

  function softDelete(table, id) {
    var tombs = loadTombstones();
    if (!tombs[table]) tombs[table] = {};
    tombs[table][id] = Date.now();
    storeTombstones(tombs);
  }

  function isSoftDeleted(table, id) {
    var tombs = loadTombstones();
    return !!(tombs[table] && tombs[table][id]);
  }

  function cleanOldTombstones(maxAgeMs) {
    maxAgeMs = maxAgeMs || (90 * 24 * 60 * 60 * 1000);
    var tombs = loadTombstones();
    var now = Date.now();
    var changed = false;
    Object.keys(tombs).forEach(function (table) {
      Object.keys(tombs[table]).forEach(function (id) {
        if (now - tombs[table][id] > maxAgeMs) {
          delete tombs[table][id];
          changed = true;
        }
      });
      if (Object.keys(tombs[table]).length === 0) delete tombs[table];
    });
    if (changed) storeTombstones(tombs);
    return changed;
  }

  /* ============================================================
     mergeInto — نسخه‌ی نهایی با پشتیبانی از baseDoc
     baseDoc: عکس لحظه‌ای از State کاربر قبل از هر بازنویسی
     ============================================================ */
  function mergeInto(cloudTables, localWins, baseDoc) {
    var info = baseDoc ? { doc: baseDoc } : readDoc();
    var doc = info.doc || defaultDoc();
    var localTables = toTables(doc);
    var snap = loadSnap();
    var out = {};
    APP_TABLES.forEach(function (n) {
      out[n] = mergeRows(snap[n], cloudTables[n] || [], localTables[n] || [], localWins);
    });
    out.meta = (cloudTables.meta || []).slice();

    var next = fromTables(out);
    var lT = doc._savedAt || 0, cT = cloudSavedAt(cloudTables);
    next._savedAt = Math.max(lT, cT) || lT || cT || 0;
    return {
      changed: sig(out) !== sig(localTables),
      doc: next,
      tables: out
    };
  }

  function apply(result) {
    if (!result || !result.changed) return false;
    writeDoc(result.doc);
    if (S.mounted && typeof window.__ktdSetData === 'function') {
      var d = result.doc;
      try { if (typeof normalizeData === 'function') d = normalizeData(result.doc); } catch (e) {}
      try { window.__ktdSetData(d); } catch (e) { console.warn('[ktd-sync] setData failed', e); }
    }
    return true;
  }

  /* ---------------- transport ---------------- */

  function headers() {
    return { 'Content-Type': 'application/json', 'X-API-Key': API_KEY };
  }

  function readJson(res) {
    var ct = (res.headers.get('content-type') || '');
    if (!res.ok) throw new Error('HTTP ' + res.status);
    if (ct.indexOf('json') === -1) throw new Error('پاسخ غیرمنتظره از سرور');
    return res.json();
  }

  function withTimeout(ms) {
    if (typeof AbortController === 'undefined') return { ctrl: null, clear: function () {} };
    var ctrl = new AbortController();
    var t = setTimeout(function () { try { ctrl.abort(); } catch (e) {} }, ms);
    return { ctrl: ctrl, clear: function () { clearTimeout(t); } };
  }

  function pull(timeout) {
    var to = withTimeout(timeout || PULL_TIMEOUT);
    return fetch(API_BASE + '/api/dump', {
      method: 'GET', headers: headers(), cache: 'no-store', signal: to.ctrl ? to.ctrl.signal : undefined
    })
      .then(readJson)
      .then(function (d) {
        to.clear();
        if (!d || typeof d !== 'object' || !d.tables) throw new Error('bad payload');
        var t = emptyTables();
        SYNC_TABLES.forEach(function (n) {
          var rows = Array.isArray(d.tables[n]) ? d.tables[n] : [];
          t[n] = rows.filter(function (r) { return r && r.id; });
        });
        return { ok: true, tables: t };
      })
      .catch(function (e) {
        to.clear();
        return { ok: false, err: (e && e.message) || 'request failed' };
      });
  }

  function cloudOn() { return !!API_BASE && !!API_KEY; }

  /* ---------------- user feedback ---------------- */

  function warn(msg) {
    if (S.warned) return;
    S.warned = true;
    console.warn('[ktd-sync]', msg);
    try {
      var el = document.createElement('div');
      el.textContent = msg;
      el.setAttribute('role', 'status');
      el.style.cssText = 'position:fixed;z-index:99999;left:50%;bottom:22px;transform:translateX(-50%);' +
        'background:#1A1A1A;color:#fff;border:1px solid #3A3A3A;border-radius:12px;padding:11px 18px;' +
        'font-size:13px;line-height:1.7;box-shadow:0 10px 34px rgba(0,0,0,.55);max-width:92vw;text-align:center;' +
        "font-family:'Vazirmatn',sans-serif;opacity:0;transition:opacity .3s";
      document.body.appendChild(el);
      requestAnimationFrame(function () { el.style.opacity = '1'; });
      setTimeout(function () {
        el.style.opacity = '0';
        setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 400);
      }, 3600);
    } catch (e) {}
  }

  function hideSplash() {
    try {
      var el = document.getElementById('bootSplash');
      if (el && el.parentNode) el.parentNode.removeChild(el);
    } catch (e) {}
  }

  /* ---------------- reconcile ---------------- */

  function reconcile(res) {
    S.pulled = true;
    var cloud = res.tables;
    var info = readDoc();
    var doc = info.doc || defaultDoc();
    var localTables = toTables(doc);

    if (!cloudHasAny(cloud)) {
      storeSnap(emptyTables());
      S.lastSig = null;
      S.origin = 'storage';
      if (hasData(localTables)) S.dirty = true;
      return;
    }

    if (info.origin === 'seed') {
      var taken = fromTables(cloud);
      taken._savedAt = cloudSavedAt(cloud) || doc._savedAt || Date.now();
      storeSnap(cloud);
      S.lastSig = sig(toTables(taken));
      writeDoc(taken);
      S.origin = 'storage';
      return;
    }

    var cT = cloudSavedAt(cloud);
    var lT = doc._savedAt || 0;
    var localWins = cT > 0 && lT > cT;
    var merged = mergeInto(cloud, localWins);
    apply(merged);
    storeSnap(cloud);
    S.lastSig = sig(cloud);
    S.origin = 'storage';
    if (sig(merged.tables) !== sig(cloud)) S.dirty = true;
  }

  function retryLater(fn) {
    if (retryTimer) return;
    retryTimer = setTimeout(function () { retryTimer = null; fn(); }, RETRY_DELAY);
  }

  function pullAgain() {
    if (!cloudOn()) return Promise.resolve();
    return pull().then(function (res) {
      if (!res.ok) {
        if (S.queued || S.dirty) retryLater(pullAgain);
        return;
      }
      reconcile(res);
      if (S.dirty) queuePush();
    });
  }

  /* ---------------- push ---------------- */

  function queuePush() {
    if (!cloudOn()) return;
    S.editGen++;
    S.dirty = true;
    if (!S.pulled) {
      S.queued = true;
      retryLater(pullAgain);
      return;
    }
    clearTimeout(pushTimer);
    pushTimer = setTimeout(push, PUSH_DELAY);
  }

  function retryLaterPush() { retryLater(push); }

  /* pull -> reconcile -> one atomic PUT of the whole document */
  function push() {
    if (!cloudOn() || S.busy) return Promise.resolve();
    S.busy = true;
    var gen = S.editGen;
    return pull().then(function (res) {
      if (!res.ok) {
        warn('ارسال متوقف شد — اتصال برقرار نیست؛ داده‌ها روی همین دستگاه می‌مانند');
        if (S.dirty) retryLaterPush();
        return;
      }
      S.pulled = true;
      var cloud = res.tables;
      var out;

      if (cloudHasAny(cloud)) {
        // ============ عکس لحظه‌ای از State کاربر قبل از هر بازنویسی ============
        var beforeInfo = readDoc();
        var beforeDoc = beforeInfo.doc || defaultDoc();

        // مرحله ۱: با سرور reconcile کن (localWins=false) تا حذف‌های ریموت پاک بشن
        var reconciled = mergeInto(cloud, false);
        if (reconciled.changed) apply(reconciled);

        // مرحله ۲: از نسخه‌ی اصلی beforeDoc استفاده کن (نه از localStorage که تازه بازنویسی شده)
        var merged = mergeInto(cloud, true, beforeDoc);
        out = merged.tables;
        apply(merged);
      } else {
        var info = readDoc();
        out = toTables(info.doc || defaultDoc());
        storeSnap(emptyTables());
      }

      out.meta = [{ id: 'main', savedAt: Date.now() }];

      return fetch(API_BASE + '/api/dump', {
        method: 'PUT', headers: headers(), body: JSON.stringify({ tables: out }), cache: 'no-store'
      })
        .then(readJson)
        .then(function () {
          S.lastSig = sig(out);
          storeSnap(out);
          S.queued = false;
          if (S.editGen === gen) S.dirty = false; else retryLaterPush();
          console.log('[ktd-sync] pushed ✓', {
            tables: Object.keys(out).reduce(function (a, k) { a[k] = (out[k] || []).length; return a; }, {})
          });
        });
    })
      .catch(function (e) {
        warn('ارسال ابری ناموفق بود: ' + ((e && e.message) || 'خطای ناشناخته'));
        if (S.dirty) retryLaterPush();
      })
      .finally(function () { S.busy = false; });
  }

  /* ---------------- hooks into the app ---------------- */

  function armHook() {
    if (Storage.prototype.__ktdHooked) return;
    var orig = Storage.prototype.setItem;
    Storage.prototype.setItem = function (key, value) {
      var r = orig.apply(this, arguments);
      try {
        if (key !== STORAGE_KEY || S.selfWrite) return r;
        var s = sig(toTables(JSON.parse(value)));
        if (!S.armed) { S.armed = true; S.mountSig = s; }
        else if (s !== S.mountSig) { S.origin = 'storage'; }
        if (s !== S.lastSig) queuePush();
      } catch (e) {}
      return r;
    };
    Storage.prototype.__ktdHooked = true;
  }

  function boot() {
    var work;
    if (!cloudOn()) { S.pulled = true; work = Promise.resolve(); }
    else {
      work = pull(BOOT_TIMEOUT)
        .then(function (res) {
          if (!res.ok) {
            warn('همگام‌سازی ابری در دسترس نیست — داده‌ها روی همین دستگاه ذخیره و بعداً ارسال می‌شود');
            if (S.queued || S.dirty) retryLater(pullAgain);
            return;
          }
          reconcile(res);
        })
        .catch(function (e) { console.warn('[ktd-sync] boot failed', e); });
    }
    return work.then(hideSplash, hideSplash);
  }

  function start() {
    S.mounted = true;
    armHook();
    window.addEventListener('online', function () {
      S.warned = false; // اجازه بده دوباره هشدار بده اگه بازم قطع شد
      if (!S.pulled) { pullAgain(); return; }
      if (S.dirty && !S.busy) queuePush();
    });
    setInterval(function () {
      if (typeof navigator !== 'undefined' && navigator.onLine === false) return;
      if (!S.pulled) { pullAgain(); return; }
      if (S.dirty && !S.busy) queuePush();
    }, 20000);
    if (S.dirty) queuePush();
  }

  window.KTD_SYNC = {
    boot: boot,
    start: start,
    state: function () { return S; },
    push: push,
    pull: pullAgain,
    softDelete: softDelete,
    isSoftDeleted: isSoftDeleted,
    tombstones: loadTombstones
  };
})();
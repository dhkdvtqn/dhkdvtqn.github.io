// ============================================================================
// VNPT - He thong quan ly chi tra hoa hong kenh diem uy quyen
// Cloudflare Worker ket noi CSDL Cloudflare D1 (binding: DB)
// Bien moi truong (Secret): AUTH_SECRET - khoa bi mat ky token dang nhap
// ============================================================================

const TOKEN_TTL_SECONDS = 12 * 60 * 60; // Token dang nhap co hieu luc 12 gio

// ---------------------------------------------------------------------------
// Cong cu ma hoa
// ---------------------------------------------------------------------------
function b64urlEncodeBytes(bytes) {
  let bin = "";
  bytes.forEach((b) => (bin += String.fromCharCode(b)));
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlEncodeText(text) {
  return b64urlEncodeBytes(new TextEncoder().encode(text));
}
function b64urlDecodeText(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}
async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function hashPassword(password, salt) {
  return sha256Hex(salt + ":" + password);
}
function randomSalt() {
  const a = new Uint8Array(12);
  crypto.getRandomValues(a);
  return [...a].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function getSecret(env) {
  return env.AUTH_SECRET || "vnpt-secret-mac-dinh-hay-dat-secret-rieng";
}
async function signToken(env, payload) {
  const header = b64urlEncodeText(JSON.stringify({ alg: "HS256", typ: "JWT" }));
  const body = b64urlEncodeText(JSON.stringify(payload));
  const data = header + "." + body;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(getSecret(env)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return data + "." + b64urlEncodeBytes(new Uint8Array(sig));
}
async function verifyToken(env, token) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const data = parts[0] + "." + parts[1];
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(getSecret(env)),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
    if (b64urlEncodeBytes(new Uint8Array(sig)) !== parts[2]) return null;
    const payload = JSON.parse(b64urlDecodeText(parts[1]));
    if (!payload.exp || payload.exp * 1000 < Date.now()) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Cong cu HTTP
// ---------------------------------------------------------------------------
function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Authorization",
    },
  });
}
function err(message, status = 400) {
  return json({ ok: false, error: message }, status);
}
async function readBody(request) {
  try {
    return await request.json();
  } catch (e) {
    return {};
  }
}
async function requireAuth(request, env) {
  const h = request.headers.get("Authorization") || "";
  const m = h.match(/^Bearer\s+(.+)$/i);
  if (!m) return null;
  const payload = await verifyToken(env, m[1]);
  if (!payload) return null;
  const user = await env.DB.prepare(
    "SELECT id, ma_kenh, ho_ten, username, role, so_eload, so_vi, can_import, active FROM nguoi_dung WHERE id = ?"
  )
    .bind(payload.sub)
    .first();
  if (!user || !user.active) return null;
  return user;
}
function publicUser(u) {
  return {
    id: u.id,
    ma_kenh: u.ma_kenh || "",
    ho_ten: u.ho_ten,
    username: u.username,
    role: u.role,
    so_eload: u.so_eload || "",
    so_vi: u.so_vi || "",
    can_import: !!u.can_import,
  };
}
function toNumber(v) {
  if (v === null || v === undefined || v === "") return 0;
  if (typeof v === "number") return v;
  const n = parseFloat(String(v).replace(/[^\d.,-]/g, "").replace(/\./g, "").replace(",", "."));
  return isNaN(n) ? 0 : n;
}
function toText(v) {
  if (v === null || v === undefined) return "";
  return String(v).trim();
}

// ---------------------------------------------------------------------------
// Dinh nghia cot cua 2 bang du lieu dau vao
// ---------------------------------------------------------------------------
const HHBG_COLUMNS = [
  ["ten_eload", "TEXT"], ["so_eload", "TEXT"], ["so_vi", "TEXT"],
  ["so_thue_bao", "TEXT"], ["loai_thue_bao", "TEXT"], ["chu_ky_chi_tra", "TEXT"],
  ["ten_goi", "TEXT"], ["gia_goi", "REAL"], ["thoi_gian_giao_dich", "TEXT"],
  ["trans_id", "TEXT"], ["kenh_thuc_hien", "TEXT"], ["thu_lao", "REAL"],
  ["ma_giao_dich", "TEXT"], ["thoi_gian_chi_tra", "TEXT"], ["trang_thai", "TEXT"],
  ["nguyen_nhan_loi", "TEXT"],
];
const BCKH_COLUMNS = [
  ["so_eload", "TEXT"], ["ten_eload", "TEXT"], ["so_thue_bao", "TEXT"],
  ["thoi_gian_kich_hoat", "TEXT"], ["hoa_hong_bckh", "REAL"],
  ["ma_giao_dich", "TEXT"], ["thoi_gian_chi_tra", "TEXT"], ["trang_thai", "TEXT"],
  ["nguyen_nhan_loi", "TEXT"],
];
function tableNameFor(loai, thang, nam) {
  const mm = String(thang).padStart(2, "0");
  if (loai === "HHBG") return "HHBG_" + mm + nam; // HHBG_MMYYYY
  return "BCKH_" + mm + String(nam).slice(-2);      // BCKH_MMYY
}
function createTableSQL(table, columns) {
  const cols = columns.map(([n, t]) => '"' + n + '" ' + t).join(", ");
  return (
    'CREATE TABLE IF NOT EXISTS "' + table + '" (id INTEGER PRIMARY KEY AUTOINCREMENT, ' +
    cols + ', imported_by TEXT, imported_at TEXT DEFAULT CURRENT_TIMESTAMP)'
  );
}
async function listMonthlyTables(env, prefix) {
  const res = await env.DB.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE ? ORDER BY name"
  )
    .bind(prefix + "_%")
    .all();
  return (res.results || []).map((r) => r.name);
}
function tableInRange(name, loai, from, to) {
  // from/to: 'YYYY-MM-DD'. Ten bang: HHBG_MMYYYY hoac BCKH_MMYY -> lay thang dau & cuoi.
  const m = name.match(/_(\d{2})(\d{2,4})$/);
  if (!m) return false;
  let year = parseInt(m[2], 10);
  if (m[2].length === 2) year += 2000;
  const month = parseInt(m[1], 10);
  const first = year + "-" + String(month).padStart(2, "0") + "-01";
  const lastDay = new Date(Date.UTC(year, month, 0)).getUTCDate();
  const last = year + "-" + String(month).padStart(2, "0") + "-" + String(lastDay).padStart(2, "0");
  return last >= from && first <= to;
}

// ---------------------------------------------------------------------------
// Xu ly chinh
// ---------------------------------------------------------------------------
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "") || "/";
    const method = request.method;

    if (method === "OPTIONS") {
      return new Response(null, {
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
    }
    if (!env.DB) return err("Worker chua duoc gan (binding) voi CSDL D1. Hay kiem tra lai buoc Binding trong huong dan.", 500);

    try {
      // ---- Kiem tra ket noi (cong khai, dung cho nut "Test ket noi") ----
      if (path === "/api/health" && method === "GET") {
        await env.DB.prepare("SELECT 1").first();
        return json({ ok: true, db: true, message: "Ket noi CSDL D1 thanh cong" });
      }

      // ---- Dang nhap ----
      if (path === "/api/login" && method === "POST") {
        const b = await readBody(request);
        const username = toText(b.username);
        const password = String(b.password || "");
        if (!username || !password) return err("Vui long nhap ten dang nhap va mat khau", 422);
        const user = await env.DB.prepare("SELECT * FROM nguoi_dung WHERE username = ?")
          .bind(username)
          .first();
        if (!user || !user.active) return err("Tai khoan khong ton tai hoac da bi khoa", 401);
        const hash = await hashPassword(password, user.salt);
        if (hash !== user.password_hash) return err("Mat khau khong dung", 401);
        const token = await signToken(env, {
          sub: user.id,
          username: user.username,
          role: user.role,
          exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS,
        });
        return json({ ok: true, token, user: publicUser(user) });
      }

      // ---- Cac API con lai deu can dang nhap ----
      const me = await requireAuth(request, env);
      if (!me) return err("Phien dang nhap khong hop le hoac da het han. Vui long dang nhap lai.", 401);
      const isAdmin = me.role === "admin";

      if (path === "/api/me" && method === "GET") {
        return json({ ok: true, user: publicUser(me) });
      }

      // ---- Quan ly don vi ----
      if (path === "/api/units" && method === "GET") {
        const res = await env.DB.prepare(
          "SELECT id, ma_don_vi, ten_don_vi, parent_id FROM don_vi ORDER BY ma_don_vi"
        ).all();
        return json({ ok: true, units: res.results || [] });
      }
      if (path === "/api/units" && method === "POST") {
        if (!isAdmin) return err("Chi admin moi co quyen tao don vi", 403);
        const b = await readBody(request);
        if (!toText(b.ma_don_vi) || !toText(b.ten_don_vi)) return err("Thieu ma don vi hoac ten don vi", 422);
        const r = await env.DB.prepare(
          "INSERT INTO don_vi (ma_don_vi, ten_don_vi, parent_id) VALUES (?, ?, ?)"
        )
          .bind(toText(b.ma_don_vi), toText(b.ten_don_vi), b.parent_id ? Number(b.parent_id) : null)
          .run();
        return json({ ok: true, id: r.meta.last_row_id });
      }
      const unitMatch = path.match(/^\/api\/units\/(\d+)$/);
      if (unitMatch && method === "PUT") {
        if (!isAdmin) return err("Chi admin moi co quyen sua don vi", 403);
        const b = await readBody(request);
        await env.DB.prepare("UPDATE don_vi SET ma_don_vi = ?, ten_don_vi = ?, parent_id = ? WHERE id = ?")
          .bind(toText(b.ma_don_vi), toText(b.ten_don_vi), b.parent_id ? Number(b.parent_id) : null, Number(unitMatch[1]))
          .run();
        return json({ ok: true });
      }
      if (unitMatch && method === "DELETE") {
        if (!isAdmin) return err("Chi admin moi co quyen xoa don vi", 403);
        await env.DB.prepare("UPDATE don_vi SET parent_id = NULL WHERE parent_id = ?").bind(Number(unitMatch[1])).run();
        await env.DB.prepare("DELETE FROM don_vi WHERE id = ?").bind(Number(unitMatch[1])).run();
        return json({ ok: true });
      }

      // ---- Quan ly nguoi dung (chi admin) ----
      if (path === "/api/users" && method === "GET") {
        if (!isAdmin) return err("Chi admin moi co quyen xem danh sach nguoi dung", 403);
        const res = await env.DB.prepare(
          "SELECT id, ma_kenh, ho_ten, username, role, so_eload, so_vi, can_import, active FROM nguoi_dung ORDER BY ho_ten"
        ).all();
        return json({ ok: true, users: (res.results || []).map(publicUser) });
      }
      if (path === "/api/users" && method === "POST") {
        if (!isAdmin) return err("Chi admin moi co quyen tao nguoi dung", 403);
        const b = await readBody(request);
        if (!toText(b.ho_ten) || !toText(b.username)) return err("Thieu ho ten hoac user dang nhap", 422);
        const salt = randomSalt();
        const password = String(b.password || "Vnpt@2026");
        const hash = await hashPassword(password, salt);
        const r = await env.DB.prepare(
          "INSERT INTO nguoi_dung (ma_kenh, ho_ten, username, password_hash, salt, role, so_eload, so_vi, can_import) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
          .bind(
            toText(b.ma_kenh), toText(b.ho_ten), toText(b.username), hash, salt,
            b.role === "admin" ? "admin" : "user",
            toText(b.so_eload), toText(b.so_vi), b.can_import ? 1 : 0
          )
          .run();
        return json({ ok: true, id: r.meta.last_row_id });
      }
      const userMatch = path.match(/^\/api\/users\/(\d+)$/);
      if (userMatch && method === "PUT") {
        if (!isAdmin) return err("Chi admin moi co quyen sua nguoi dung", 403);
        const b = await readBody(request);
        await env.DB.prepare(
          "UPDATE nguoi_dung SET ma_kenh = ?, ho_ten = ?, so_eload = ?, so_vi = ?, can_import = ?, role = ?, active = ? WHERE id = ?"
        )
          .bind(
            toText(b.ma_kenh), toText(b.ho_ten), toText(b.so_eload), toText(b.so_vi),
            b.can_import ? 1 : 0, b.role === "admin" ? "admin" : "user",
            b.active === false ? 0 : 1, Number(userMatch[1])
          )
          .run();
        if (b.password) {
          const salt = randomSalt();
          const hash = await hashPassword(String(b.password), salt);
          await env.DB.prepare("UPDATE nguoi_dung SET password_hash = ?, salt = ? WHERE id = ?")
            .bind(hash, salt, Number(userMatch[1]))
            .run();
        }
        return json({ ok: true });
      }
      if (userMatch && method === "DELETE") {
        if (!isAdmin) return err("Chi admin moi co quyen xoa nguoi dung", 403);
        if (Number(userMatch[1]) === me.id) return err("Khong the tu xoa tai khoan dang dang nhap", 422);
        await env.DB.prepare("DELETE FROM nguoi_dung WHERE id = ?").bind(Number(userMatch[1])).run();
        return json({ ok: true });
      }

      // ---- Import du lieu dau vao tu Excel ----
      if (path === "/api/import/tables" && method === "GET") {
        const hhbg = await listMonthlyTables(env, "HHBG");
        const bckh = await listMonthlyTables(env, "BCKH");
        const out = [];
        for (const t of [...hhbg, ...bckh]) {
          const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM "' + t + '"').first();
          out.push({ table: t, rows: c ? c.n : 0 });
        }
        return json({ ok: true, tables: out });
      }
      // ---- Xoa bang du lieu da import ----
      const tblMatch = path.match(/^\/api\/import\/tables\/([A-Za-z0-9_]+)$/);
      if (tblMatch && method === "DELETE") {
        if (!isAdmin && !me.can_import) return err("Tai khoan khong co quyen xoa bang du lieu", 403);
        const name = tblMatch[1];
        if (!/^(HHBG|BCKH)_\d{4,6}$/.test(name)) return err("Ten bang khong hop le", 422);
        await env.DB.prepare('DROP TABLE IF EXISTS "' + name + '"').run();
        return json({ ok: true, table: name });
      }
      if (path === "/api/import" && method === "POST") {
        if (!isAdmin && !me.can_import) return err("Tai khoan khong co quyen import du lieu", 403);
        const b = await readBody(request);
        const loai = b.loai === "BCKH" ? "BCKH" : "HHBG";
        const mode = b.mode === "replace" ? "replace" : "append"; // append = Cap nhat, replace = Thay the
        const thang = Number(b.thang);
        const nam = Number(b.nam);
        const columns = loai === "HHBG" ? HHBG_COLUMNS : BCKH_COLUMNS;
        const colNames = columns.map(([n]) => n);
        // Chi giu cac truong khop voi bang map du lieu; dong rong bi loai bo.
        const rawRows = Array.isArray(b.rows) ? b.rows : [];
        const rows = rawRows.filter((row) => {
          if (!row || typeof row !== "object") return false;
          return colNames.some((n) => {
            const v = row[n];
            return v !== null && v !== undefined && String(v).trim() !== "";
          });
        });
        if (!thang || thang < 1 || thang > 12 || !nam) return err("Thang/nam import khong hop le", 422);
        if (!rows.length) return err("Khong co dong du lieu nao de import", 422);
        const table = tableNameFor(loai, thang, nam);
        if (mode === "replace") {
          await env.DB.prepare('DROP TABLE IF EXISTS "' + table + '"').run();
        }
        await env.DB.prepare(createTableSQL(table, columns)).run();
        const numericCols = new Set(columns.filter(([, t]) => t === "REAL").map(([n]) => n));
        const sql =
          'INSERT INTO "' + table + '" (' + colNames.map((n) => '"' + n + '"').join(", ") +
          ", imported_by) VALUES (" + colNames.map(() => "?").join(", ") + ", ?)";
        let inserted = 0;
        const CHUNK = 100;
        for (let i = 0; i < rows.length; i += CHUNK) {
          const batch = rows.slice(i, i + CHUNK).map((row) => {
            const vals = colNames.map((n) => {
              const v = row[n];
              return numericCols.has(n) ? toNumber(v) : toText(v);
            });
            vals.push(me.username);
            return env.DB.prepare(sql).bind(...vals);
          });
          await env.DB.batch(batch);
          inserted += batch.length;
        }
        return json({ ok: true, table, inserted, mode });
      }

      // ---- Bao cao thong ke ----
      if (path === "/api/reports/summary" && method === "GET") {
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        const group = url.searchParams.get("group") || "day";
        const loai = (url.searchParams.get("loai") || "ALL").toUpperCase();
        const groupExpr =
          group === "month"
            ? "substr(tg, 1, 7)"
            : group === "week"
            ? "strftime('%Y-W%W', date(substr(tg, 1, 10)))"
            : "substr(tg, 1, 10)";
        const parts = [];
        const binds = [];
        const sources = [];
        if (loai === "ALL" || loai === "HHBG") sources.push({ prefix: "HHBG", money: "thu_lao", time: "COALESCE(NULLIF(thoi_gian_chi_tra, ''), thoi_gian_giao_dich)", own: "(so_eload = ? OR so_vi = ?)", ownBinds: [me.so_eload || "__none__", me.so_vi || "__none__"] });
        if (loai === "ALL" || loai === "BCKH") sources.push({ prefix: "BCKH", money: "hoa_hong_bckh", time: "thoi_gian_chi_tra", own: "(so_eload = ?)", ownBinds: [me.so_eload || "__none__"] });
        for (const s of sources) {
          const tables = await listMonthlyTables(env, s.prefix);
          for (const t of tables) {
            if (!tableInRange(t, s.prefix, from, to)) continue;
            let sql =
              'SELECT ' + groupExpr + ' AS ky, COUNT(*) AS so_giao_dich, COALESCE(SUM(tien), 0) AS tong_tien FROM (SELECT ' +
              s.time + ' AS tg, ' + s.money + ' AS tien, so_eload' + (s.prefix === "HHBG" ? ", so_vi" : "") +
              ' FROM "' + t + '") WHERE substr(tg, 1, 10) BETWEEN ? AND ?';
            const localBinds = [from, to];
            if (!isAdmin) {
              sql += " AND " + s.own;
              localBinds.push(...s.ownBinds);
            }
            sql += " GROUP BY ky";
            parts.push(sql);
            binds.push(...localBinds);
          }
        }
        if (!parts.length) return json({ ok: true, rows: [], tong_giao_dich: 0, tong_tien: 0 });
        const union = parts.join(" UNION ALL ");
        const res = await env.DB.prepare(
          "SELECT ky, SUM(so_giao_dich) AS so_giao_dich, SUM(tong_tien) AS tong_tien FROM (" + union + ") GROUP BY ky ORDER BY ky"
        )
          .bind(...binds)
          .all();
        const rows = res.results || [];
        return json({
          ok: true,
          rows,
          tong_giao_dich: rows.reduce((a, r) => a + (r.so_giao_dich || 0), 0),
          tong_tien: rows.reduce((a, r) => a + (r.tong_tien || 0), 0),
        });
      }
      if (path === "/api/reports/detail" && method === "GET") {
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        const loai = (url.searchParams.get("loai") || "ALL").toUpperCase();
        const limit = Math.min(Number(url.searchParams.get("limit") || 500), 2000);
        const out = [];
        const sources = [];
        if (loai === "ALL" || loai === "HHBG") sources.push({ prefix: "HHBG", money: "thu_lao", time: "COALESCE(NULLIF(thoi_gian_chi_tra, ''), thoi_gian_giao_dich)", own: "(so_eload = ? OR so_vi = ?)", ownBinds: [me.so_eload || "__none__", me.so_vi || "__none__"], extra: ", ten_goi, gia_goi" });
        if (loai === "ALL" || loai === "BCKH") sources.push({ prefix: "BCKH", money: "hoa_hong_bckh", time: "thoi_gian_chi_tra", own: "(so_eload = ?)", ownBinds: [me.so_eload || "__none__"], extra: ", '' AS ten_goi, 0 AS gia_goi" });
        for (const s of sources) {
          const tables = await listMonthlyTables(env, s.prefix);
          for (const t of tables) {
            if (!tableInRange(t, s.prefix, from, to)) continue;
            let sql =
              "SELECT '" + s.prefix + "' AS loai, so_thue_bao, so_eload, " + s.money + " AS so_tien, ma_giao_dich, " +
              s.time + " AS thoi_gian, trang_thai, nguyen_nhan_loi" + s.extra +
              ' FROM "' + t + '" WHERE substr(' + s.time + ", 1, 10) BETWEEN ? AND ?";
            const binds = [from, to];
            if (!isAdmin) {
              sql += " AND " + s.own;
              binds.push(...s.ownBinds);
            }
            sql += " ORDER BY thoi_gian DESC LIMIT ?";
            binds.push(limit);
            const res = await env.DB.prepare(sql).bind(...binds).all();
            out.push(...(res.results || []));
          }
        }
        out.sort((a, b) => String(b.thoi_gian || "").localeCompare(String(a.thoi_gian || "")));
        return json({ ok: true, rows: out.slice(0, limit) });
      }

      // ---- Cai dat tai khoan ----
      if (path === "/api/settings/password" && method === "POST") {
        const b = await readBody(request);
        const full = await env.DB.prepare("SELECT * FROM nguoi_dung WHERE id = ?").bind(me.id).first();
        const oldHash = await hashPassword(String(b.old_password || ""), full.salt);
        if (oldHash !== full.password_hash) return err("Mat khau cu khong dung", 422);
        if (!b.new_password || String(b.new_password).length < 8) return err("Mat khau moi phai co it nhat 8 ky tu", 422);
        const salt = randomSalt();
        const hash = await hashPassword(String(b.new_password), salt);
        await env.DB.prepare("UPDATE nguoi_dung SET password_hash = ?, salt = ? WHERE id = ?")
          .bind(hash, salt, me.id)
          .run();
        return json({ ok: true });
      }
      if (path === "/api/settings/contact" && method === "POST") {
        const b = await readBody(request);
        await env.DB.prepare("UPDATE nguoi_dung SET so_eload = ?, so_vi = ? WHERE id = ?")
          .bind(toText(b.so_eload), toText(b.so_vi), me.id)
          .run();
        return json({ ok: true });
      }

      return err("Khong tim thay chuc nang: " + path, 404);
    } catch (e) {
      return err("Loi he thong: " + (e && e.message ? e.message : String(e)), 500);
    }
  },
};

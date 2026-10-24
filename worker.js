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
    "SELECT id, ma_kenh, ho_ten, username, role, so_eload, so_vi, ten_nhan_vien, sdt_nhan_vien, don_vi_id, can_import, active FROM nguoi_dung WHERE id = ?"
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
    ten_nhan_vien: u.ten_nhan_vien || "",
    sdt_nhan_vien: u.sdt_nhan_vien || "",
    don_vi_id: u.don_vi_id ?? null,
    don_vi_ten: u.don_vi_ten || "",
    can_import: !!u.can_import,
  };
}
// Tu dong bo sung 2 cot nhan vien quan ly neu CSDL cu chua co (nang cap tai cho).
async function ensureUserColumns(env) {
  try {
    const res = await env.DB.prepare("PRAGMA table_info(nguoi_dung)").all();
    const cols = new Set((res.results || []).map((r) => r.name));
    if (!cols.has("ten_nhan_vien")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN ten_nhan_vien TEXT").run();
    if (!cols.has("sdt_nhan_vien")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN sdt_nhan_vien TEXT").run();
    if (!cols.has("don_vi_id")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN don_vi_id INTEGER").run();
  } catch (e) { /* bo qua neu bang chua ton tai */ }
}
function saigonNow() {
  const d = new Date(Date.now() + 7 * 3600 * 1000);
  return d.toISOString().replace("T", " ").slice(0, 19);
}
async function ensureLoginLog(env) {
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS dang_nhap_log (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, ho_ten TEXT, thoi_gian TEXT)"
  ).run();
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
// Loai du lieu dau vao: 2 loai mac dinh (HHBG, BCKH) + cac loai admin tu tao.
// Moi loai duoc luu trong bang loai_du_lieu tren D1 (so dang ky), gom:
// - columns: danh sach cot [{key, label, type}] type: text | money | date
// - cac cot "vai tro" de bao cao va phan quyen: money_col (so tien chi tra),
//   time_col (thoi gian loc bao cao), eload_col / vi_col (map voi bang
//   nguoi_dung qua so_eload / so_vi), sub_col, pkg_col, trans_col,
//   status_col, reason_col.
// ---------------------------------------------------------------------------
const BUILTIN_TYPES = [
  {
    code: "HHBG", name: "Chi trả hoa hồng bán gói", prefix: "HHBG", fmt: "MMYYYY", builtin: 1,
    columns: [
      { key: "ten_eload", label: "Tên Eload", type: "text" },
      { key: "so_eload", label: "Số Eload", type: "text" },
      { key: "so_vi", label: "Số Ví", type: "text" },
      { key: "so_thue_bao", label: "Số thuê bao", type: "text" },
      { key: "loai_thue_bao", label: "Loại thuê bao", type: "text" },
      { key: "chu_ky_chi_tra", label: "Chu kỳ chi trả", type: "text" },
      { key: "ten_goi", label: "Tên gói cước", type: "text" },
      { key: "gia_goi", label: "Giá gói cước", type: "money" },
      { key: "thoi_gian_giao_dich", label: "Thời gian giao dịch", type: "date" },
      { key: "trans_id", label: "Trans ID", type: "text" },
      { key: "kenh_thuc_hien", label: "Kênh thực hiện", type: "text" },
      { key: "thu_lao", label: "Thù lao chi trả", type: "money" },
      { key: "ma_giao_dich", label: "Mã giao dịch", type: "text" },
      { key: "thoi_gian_chi_tra", label: "Thời gian chi trả", type: "date" },
      { key: "trang_thai", label: "Trạng thái chi trả", type: "text" },
      { key: "nguyen_nhan_loi", label: "Nguyên nhân lỗi", type: "text" },
    ],
    money_col: "thu_lao", time_col: "thoi_gian_chi_tra", time_fallback_col: "thoi_gian_giao_dich",
    eload_col: "so_eload", vi_col: "so_vi", sub_col: "so_thue_bao", pkg_col: "ten_goi",
    trans_col: "ma_giao_dich", status_col: "trang_thai", reason_col: "nguyen_nhan_loi",
  },
  {
    code: "BCKH", name: "Chi trả tiền BCKH", prefix: "BCKH", fmt: "MMYY", builtin: 1,
    columns: [
      { key: "so_eload", label: "Số Eload", type: "text" },
      { key: "ten_eload", label: "Tên Eload", type: "text" },
      { key: "so_thue_bao", label: "Số thuê bao", type: "text" },
      { key: "thoi_gian_kich_hoat", label: "Thời gian kích hoạt", type: "date" },
      { key: "hoa_hong_bckh", label: "Hoa hồng BCKH", type: "money" },
      { key: "ma_giao_dich", label: "Mã giao dịch", type: "text" },
      { key: "thoi_gian_chi_tra", label: "Thời gian chi trả", type: "date" },
      { key: "trang_thai", label: "Trạng thái chi trả", type: "text" },
      { key: "nguyen_nhan_loi", label: "Nguyên nhân lỗi", type: "text" },
    ],
    money_col: "hoa_hong_bckh", time_col: "thoi_gian_chi_tra", time_fallback_col: "",
    eload_col: "so_eload", vi_col: "", sub_col: "so_thue_bao", pkg_col: "",
    trans_col: "ma_giao_dich", status_col: "trang_thai", reason_col: "nguyen_nhan_loi",
  },
];
async function ensureTypes(env) {
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS loai_du_lieu (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, " +
    "prefix TEXT NOT NULL, fmt TEXT NOT NULL DEFAULT 'MMYYYY', columns_json TEXT NOT NULL, " +
    "money_col TEXT, time_col TEXT, time_fallback_col TEXT, eload_col TEXT, vi_col TEXT, " +
    "sub_col TEXT, pkg_col TEXT, trans_col TEXT, status_col TEXT, reason_col TEXT, " +
    "builtin INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
  ).run();
  const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM loai_du_lieu").first();
  if (c && c.n === 0) {
    for (const t of BUILTIN_TYPES) {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO loai_du_lieu (code, name, prefix, fmt, columns_json, money_col, time_col, time_fallback_col, eload_col, vi_col, sub_col, pkg_col, trans_col, status_col, reason_col, builtin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)"
      )
        .bind(t.code, t.name, t.prefix, t.fmt, JSON.stringify(t.columns), t.money_col, t.time_col, t.time_fallback_col, t.eload_col, t.vi_col, t.sub_col, t.pkg_col, t.trans_col, t.status_col, t.reason_col)
        .run();
    }
  }
}
async function getDataTypes(env) {
  await ensureTypes(env);
  const res = await env.DB.prepare("SELECT * FROM loai_du_lieu ORDER BY builtin DESC, code").all();
  return (res.results || []).map((r) => {
    let cols = [];
    try { cols = JSON.parse(r.columns_json || "[]"); } catch (e) { cols = []; }
    return { ...r, columns: cols, builtin: !!r.builtin };
  });
}
function typeColumnsSQL(t) {
  return (t.columns || []).map((c) => [c.key, c.type === "money" || c.type === "number" ? "REAL" : "TEXT"]);
}
// Dung "nguon bao cao" tu 1 loai du lieu: cot tien, cot thoi gian va dieu kien
// phan quyen (user thuong chi thay dong co so_eload / so_vi cua chinh minh).
function buildSource(t, meUser) {
  const time = t.time_fallback_col
    ? "COALESCE(NULLIF(" + t.time_col + ", ''), " + t.time_fallback_col + ")"
    : t.time_col;
  const ownParts = [], ownBinds = [];
  if (t.eload_col) { ownParts.push(t.eload_col + " = ?"); ownBinds.push(meUser.so_eload || "__none__"); }
  if (t.vi_col) { ownParts.push(t.vi_col + " = ?"); ownBinds.push(meUser.so_vi || "__none__"); }
  return {
    code: t.code, prefix: t.prefix, money: t.money_col, time,
    own: ownParts.length ? "(" + ownParts.join(" OR ") + ")" : "(1 = 0)",
    ownBinds,
    eloadCol: t.eload_col || null, viCol: t.vi_col || null,
    subCol: t.sub_col || null, pkgCol: t.pkg_col || null,
    transCol: t.trans_col || null, statusCol: t.status_col || null, reasonCol: t.reason_col || null,
  };
}
function tableNameForType(t, thang, nam) {
  const mm = String(thang).padStart(2, "0");
  return t.prefix + "_" + mm + (t.fmt === "MMYY" ? String(nam).slice(-2) : nam);
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
        // Ghi log dang nhap (phuc vu module Thong ke dang nhap)
        try {
          await ensureLoginLog(env);
          await env.DB.prepare("INSERT INTO dang_nhap_log (user_id, username, ho_ten, thoi_gian) VALUES (?, ?, ?, ?)")
            .bind(user.id, user.username, user.ho_ten, saigonNow())
            .run();
        } catch (e) { /* loi ghi log khong duoc chan dang nhap */ }
        const token = await signToken(env, {
          sub: user.id,
          username: user.username,
          role: user.role,
          exp: Math.floor(Date.now() / 1000) + TOKEN_TTL_SECONDS,
        });
        return json({ ok: true, token, user: publicUser(user) });
      }

      // ---- Cac API con lai deu can dang nhap ----
      await ensureUserColumns(env); // dam bao cac cot bo sung da co truoc khi truy van
      const me = await requireAuth(request, env);
      if (!me) return err("Phien dang nhap khong hop le hoac da het han. Vui long dang nhap lai.", 401);
      const isAdmin = me.role === "admin";
      const isSubAdmin = me.role === "subadmin";
      const isPrivileged = isAdmin || isSubAdmin; // Admin & SubAdmin: xem du lieu toan tinh
      const canManageUsers = isAdmin || isSubAdmin; // Admin & SubAdmin: quan ly nguoi dung

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

      // ---- Quan ly nguoi dung (admin & subadmin) ----
      if (path === "/api/users" && method === "GET") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen xem danh sach nguoi dung", 403);
        const res = await env.DB.prepare(
          "SELECT u.id, u.ma_kenh, u.ho_ten, u.username, u.role, u.so_eload, u.so_vi, u.ten_nhan_vien, u.sdt_nhan_vien, u.don_vi_id, d.ten_don_vi AS don_vi_ten, u.can_import, u.active FROM nguoi_dung u LEFT JOIN don_vi d ON d.id = u.don_vi_id ORDER BY u.ho_ten"
        ).all();
        return json({ ok: true, users: (res.results || []).map(publicUser) });
      }
      if (path === "/api/users" && method === "POST") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen tao nguoi dung", 403);
        const b = await readBody(request);
        if (!toText(b.ho_ten) || !toText(b.username)) return err("Thieu ho ten hoac user dang nhap", 422);
        const salt = randomSalt();
        const password = String(b.password || "Vnpt@2026");
        const hash = await hashPassword(password, salt);
        // Phan quyen: chi admin moi duoc dat loai tai khoan va cap quyen import;
        // SubAdmin tao nguoi dung thi mac dinh la user thuong, khong co quyen import.
        const newRole = isAdmin ? (b.role === "admin" ? "admin" : b.role === "subadmin" ? "subadmin" : "user") : "user";
        const newCanImport = isAdmin && b.can_import ? 1 : 0;
        const r = await env.DB.prepare(
          "INSERT INTO nguoi_dung (ma_kenh, ho_ten, username, password_hash, salt, role, so_eload, so_vi, ten_nhan_vien, sdt_nhan_vien, don_vi_id, can_import) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
          .bind(
            toText(b.ma_kenh), toText(b.ho_ten), toText(b.username), hash, salt,
            newRole,
            toText(b.so_eload), toText(b.so_vi), toText(b.ten_nhan_vien), toText(b.sdt_nhan_vien),
            b.don_vi_id ? Number(b.don_vi_id) : null, newCanImport
          )
          .run();
        return json({ ok: true, id: r.meta.last_row_id });
      }
      // ---- Import nguoi dung tu Excel ----
      if (path === "/api/users/import" && method === "POST") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen import nguoi dung", 403);
        const b = await readBody(request);
        const rows = Array.isArray(b.rows) ? b.rows : [];
        if (!rows.length) return err("Khong co dong du lieu nao de import", 422);
        let created = 0, skipped = 0;
        const errors = [];
        const warnings = [];
        for (let i = 0; i < rows.length; i++) {
          const r = rows[i] || {};
          const username = toText(r.username);
          const hoTen = toText(r.ho_ten);
          if (!username || !hoTen) {
            skipped++;
            errors.push({ row: i + 2, reason: "Thieu User dang nhap hoac Ho va ten" });
            continue;
          }
          const dup = await env.DB.prepare("SELECT id FROM nguoi_dung WHERE username = ?").bind(username).first();
          if (dup) {
            skipped++;
            errors.push({ row: i + 2, reason: "User dang nhap da ton tai: " + username });
            continue;
          }
          // Don vi: nhan id truc tiep, hoac tra theo ma/ten don vi trong file Excel
          let donViId = null;
          if (r.don_vi_id) donViId = Number(r.don_vi_id) || null;
          else if (toText(r.don_vi)) {
            const dv = await env.DB.prepare("SELECT id FROM don_vi WHERE ma_don_vi = ? OR ten_don_vi = ?")
              .bind(toText(r.don_vi), toText(r.don_vi))
              .first();
            if (dv) donViId = dv.id;
            else warnings.push({ row: i + 2, reason: "Khong tim thay don vi '" + toText(r.don_vi) + "' — da de trong" });
          }
          const salt = randomSalt();
          const hash = await hashPassword(String(r.password || "Vnpt@2026"), salt);
          await env.DB.prepare(
            "INSERT INTO nguoi_dung (ma_kenh, ho_ten, username, password_hash, salt, role, so_eload, so_vi, ten_nhan_vien, sdt_nhan_vien, don_vi_id, can_import) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          )
            .bind(
              toText(r.ma_kenh), hoTen, username, hash, salt,
              isAdmin ? (r.role === "admin" ? "admin" : r.role === "subadmin" ? "subadmin" : "user") : "user",
              toText(r.so_eload), toText(r.so_vi), toText(r.ten_nhan_vien), toText(r.sdt_nhan_vien), donViId, isAdmin && r.can_import ? 1 : 0
            )
            .run();
          created++;
        }
        return json({ ok: true, created, skipped, errors: errors.slice(0, 50), warnings: warnings.slice(0, 50) });
      }
      const userMatch = path.match(/^\/api\/users\/(\d+)$/);
      if (userMatch && method === "PUT") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen sua nguoi dung", 403);
        const b = await readBody(request);
        // Phan quyen: SubAdmin khong duoc thay doi loai tai khoan va quyen import
        // cua nguoi dung -> giu nguyen gia tri dang co trong CSDL.
        let newRole = b.role === "admin" ? "admin" : b.role === "subadmin" ? "subadmin" : "user";
        let newCanImport = b.can_import ? 1 : 0;
        if (!isAdmin) {
          const cur = await env.DB.prepare("SELECT role, can_import FROM nguoi_dung WHERE id = ?").bind(Number(userMatch[1])).first();
          if (cur) { newRole = cur.role; newCanImport = cur.can_import; }
        }
        await env.DB.prepare(
          "UPDATE nguoi_dung SET ma_kenh = ?, ho_ten = ?, so_eload = ?, so_vi = ?, ten_nhan_vien = ?, sdt_nhan_vien = ?, don_vi_id = ?, can_import = ?, role = ?, active = ? WHERE id = ?"
        )
          .bind(
            toText(b.ma_kenh), toText(b.ho_ten), toText(b.so_eload), toText(b.so_vi),
            toText(b.ten_nhan_vien), toText(b.sdt_nhan_vien), b.don_vi_id ? Number(b.don_vi_id) : null,
            newCanImport, newRole,
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
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen xoa nguoi dung", 403);
        if (Number(userMatch[1]) === me.id) return err("Khong the tu xoa tai khoan dang dang nhap", 422);
        await env.DB.prepare("DELETE FROM nguoi_dung WHERE id = ?").bind(Number(userMatch[1])).run();
        return json({ ok: true });
      }

      // ---- Quan ly loai du lieu dau vao ----
      if (path === "/api/datatypes" && method === "GET") {
        const types = await getDataTypes(env);
        return json({ ok: true, types });
      }
      if (path === "/api/datatypes" && method === "POST") {
        if (!isAdmin) return err("Chi admin moi co quyen tao loai du lieu", 403);
        const b = await readBody(request);
        const code = String(b.code || "").trim().toUpperCase();
        const name = toText(b.name);
        const fmt = b.fmt === "MMYY" ? "MMYY" : "MMYYYY";
        const columns = Array.isArray(b.columns) ? b.columns : [];
        if (!/^[A-Z][A-Z0-9_]{1,11}$/.test(code)) return err("Ma loai du lieu khong hop le (2-12 ky tu, bat dau bang chu cai, chi gom chu/so/_)", 422);
        if (!name) return err("Thieu ten loai du lieu", 422);
        if (!columns.length) return err("Loai du lieu phai co it nhat 1 cot", 422);
        const keys = new Set();
        for (const c of columns) {
          if (!/^[a-z][a-z0-9_]*$/.test(String(c.key || ""))) return err("Khoa cot khong hop le: " + (c.key || ""), 422);
          if (keys.has(c.key)) return err("Trung khoa cot: " + c.key, 422);
          keys.add(c.key);
        }
        const roleCols = ["money_col", "time_col", "eload_col"];
        for (const rc of roleCols) {
          if (!b[rc] || !keys.has(b[rc])) return err("Chua chon cot vai tro bat buoc: " + rc, 422);
        }
        for (const rc of ["time_fallback_col", "vi_col", "sub_col", "pkg_col", "trans_col", "status_col", "reason_col"]) {
          if (b[rc] && !keys.has(b[rc])) return err("Cot vai tro khong nam trong danh sach cot: " + rc, 422);
        }
        const exists = (await getDataTypes(env)).some((t) => t.code === code || t.prefix === code);
        if (exists) return err("Ma loai du lieu da ton tai: " + code, 422);
        const cleanCols = columns.map((c) => ({
          key: String(c.key), label: toText(c.label) || String(c.key),
          type: ["money", "number", "date"].includes(c.type) ? c.type : "text",
        }));
        const r = await env.DB.prepare(
          "INSERT INTO loai_du_lieu (code, name, prefix, fmt, columns_json, money_col, time_col, time_fallback_col, eload_col, vi_col, sub_col, pkg_col, trans_col, status_col, reason_col, builtin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)"
        )
          .bind(code, name, code, fmt, JSON.stringify(cleanCols),
            b.money_col, b.time_col, b.time_fallback_col || "", b.eload_col, b.vi_col || "",
            b.sub_col || "", b.pkg_col || "", b.trans_col || "", b.status_col || "", b.reason_col || "")
          .run();
        return json({ ok: true, id: r.meta.last_row_id, code });
      }
      const dtMatch = path.match(/^\/api\/datatypes\/(\d+)$/);
      if (dtMatch && method === "DELETE") {
        if (!isAdmin) return err("Chi admin moi co quyen xoa loai du lieu", 403);
        const t = await env.DB.prepare("SELECT * FROM loai_du_lieu WHERE id = ?").bind(Number(dtMatch[1])).first();
        if (!t) return err("Khong tim thay loai du lieu", 404);
        if (t.builtin) return err("Khong the xoa loai du lieu mac dinh cua he thong", 422);
        await env.DB.prepare("DELETE FROM loai_du_lieu WHERE id = ?").bind(Number(dtMatch[1])).run();
        return json({ ok: true });
      }

      // ---- Import du lieu dau vao tu Excel ----
      if (path === "/api/import/tables" && method === "GET") {
        const types = await getDataTypes(env);
        const out = [];
        for (const t of types) {
          const tables = await listMonthlyTables(env, t.prefix);
          for (const name of tables) {
            const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM "' + name + '"').first();
            out.push({ table: name, code: t.code, rows: c ? c.n : 0 });
          }
        }
        return json({ ok: true, tables: out });
      }
      // ---- Xoa bang du lieu da import ----
      const tblMatch = path.match(/^\/api\/import\/tables\/([A-Za-z0-9_]+)$/);
      if (tblMatch && method === "DELETE") {
        if (!isAdmin && (isSubAdmin || !me.can_import)) return err("Tai khoan khong co quyen xoa bang du lieu (SubAdmin khong duoc phep xoa bang)", 403);
        const name = tblMatch[1];
        const types = await getDataTypes(env);
        const okName = types.some((t) => new RegExp("^" + t.prefix + "_\\d{4,6}$").test(name));
        if (!okName) return err("Ten bang khong hop le", 422);
        await env.DB.prepare('DROP TABLE IF EXISTS "' + name + '"').run();
        return json({ ok: true, table: name });
      }
      if (path === "/api/import" && method === "POST") {
        if (!isAdmin && !me.can_import) return err("Tai khoan khong co quyen import du lieu", 403);
        const b = await readBody(request);
        const types = await getDataTypes(env);
        const dtype = types.find((t) => t.code === String(b.loai || "").toUpperCase());
        if (!dtype) return err("Loai du lieu khong ton tai: " + (b.loai || ""), 422);
        const mode = b.mode === "replace" ? "replace" : "append"; // append = Cap nhat, replace = Thay the
        const thang = Number(b.thang);
        const nam = Number(b.nam);
        const columns = typeColumnsSQL(dtype);
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
        const table = tableNameForType(dtype, thang, nam);
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
        const groupExpr = group === "month" ? "substr(tg, 1, 7)" : "substr(tg, 1, 10)";
        const types = await getDataTypes(env);
        const sources = types
          .filter((t) => (loai === "ALL" || t.code === loai) && t.money_col && t.time_col)
          .map((t) => buildSource(t, me));
        // Truy van tung bang thang roi cong don ket qua trong JS.
        // (Cach cu ghep tat ca bang bang UNION ALL thanh 1 cau SQL khong lo
        //  se vuot gioi han "too many terms in compound SELECT" cua D1.)
        const agg = new Map();
        for (const s of sources) {
          const tables = await listMonthlyTables(env, s.prefix);
          for (const t of tables) {
            if (!tableInRange(t, s.prefix, from, to)) continue;
            const innerCols = [s.time + " AS tg", s.money + " AS tien"];
            if (s.eloadCol) innerCols.push(s.eloadCol);
            if (s.viCol) innerCols.push(s.viCol);
            let sql =
              'SELECT ' + groupExpr + ' AS ky, COUNT(*) AS so_giao_dich, COALESCE(SUM(tien), 0) AS tong_tien FROM (SELECT ' +
              innerCols.join(", ") + ' FROM "' + t + '") WHERE substr(tg, 1, 10) BETWEEN ? AND ?';
            const localBinds = [from, to];
            if (!isPrivileged) {
              sql += " AND " + s.own;
              localBinds.push(...s.ownBinds);
            }
            sql += " GROUP BY ky";
            const res = await env.DB.prepare(sql).bind(...localBinds).all();
            for (const r of res.results || []) {
              const cur = agg.get(r.ky) || { ky: r.ky, so_giao_dich: 0, tong_tien: 0 };
              cur.so_giao_dich += r.so_giao_dich || 0;
              cur.tong_tien += r.tong_tien || 0;
              agg.set(r.ky, cur);
            }
          }
        }
        const rows = [...agg.values()].sort((a, b) => String(a.ky || "").localeCompare(String(b.ky || "")));
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
        const types = await getDataTypes(env);
        const sources = types
          .filter((t) => (loai === "ALL" || t.code === loai) && t.money_col && t.time_col)
          .map((t) => buildSource(t, me));
        for (const s of sources) {
          const tables = await listMonthlyTables(env, s.prefix);
          for (const t of tables) {
            if (!tableInRange(t, s.prefix, from, to)) continue;
            const sel = [
              "'" + s.code + "' AS loai",
              (s.subCol || "''") + " AS so_thue_bao",
              (s.eloadCol || "''") + " AS so_eload",
              s.money + " AS so_tien",
              (s.transCol || "''") + " AS ma_giao_dich",
              s.time + " AS thoi_gian",
              (s.statusCol || "''") + " AS trang_thai",
              (s.reasonCol || "''") + " AS nguyen_nhan_loi",
              (s.pkgCol || "''") + " AS ten_goi",
            ];
            let sql =
              "SELECT " + sel.join(", ") + ' FROM "' + t + '" WHERE substr(' + s.time + ", 1, 10) BETWEEN ? AND ?";
            const binds = [from, to];
            if (!isPrivileged) {
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

      // ---- Thong ke dang nhap theo thang (admin & subadmin) ----
      if (path === "/api/login-stats" && method === "GET") {
        if (!isPrivileged) return err("Chi admin/subadmin moi co quyen xem thong ke dang nhap", 403);
        await ensureLoginLog(env);
        const month = url.searchParams.get("month") || saigonNow().slice(0, 7);
        if (!/^\d{4}-\d{2}$/.test(month)) return err("Thang khong hop le (YYYY-MM)", 422);
        const res = await env.DB.prepare(
          "SELECT username, ho_ten, COUNT(*) AS so_lan, MAX(thoi_gian) AS lan_gan_nhat FROM dang_nhap_log WHERE substr(thoi_gian, 1, 7) = ? GROUP BY username, ho_ten ORDER BY so_lan DESC, ho_ten"
        )
          .bind(month)
          .all();
        const rows = res.results || [];
        return json({
          ok: true,
          month,
          rows,
          tong_luot: rows.reduce((a, r) => a + (r.so_lan || 0), 0),
          tong_nguoi: rows.length,
        });
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

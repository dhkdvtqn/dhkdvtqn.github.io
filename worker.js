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
    "SELECT id, ma_kenh, ho_ten, username, role, so_eload, so_vi, ma_hrm, ten_nhan_vien, sdt_nhan_vien, don_vi_id, can_import, modules, lat, lng, active FROM nguoi_dung WHERE id = ?"
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
    modules: parseModules(u.modules),
    lat: u.lat ?? null,
    lng: u.lng ?? null,
  };
}
// Tu dong bo sung 2 cot nhan vien quan ly neu CSDL cu chua co (nang cap tai cho).
async function ensureUserColumns(env) {
  try {
    const res = await env.DB.prepare("PRAGMA table_info(nguoi_dung)").all();
    const cols = new Set((res.results || []).map((r) => r.name));
    if (!cols.has("ten_nhan_vien")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN ten_nhan_vien TEXT").run();
    if (!cols.has("sdt_nhan_vien")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN sdt_nhan_vien TEXT").run();
    if (!cols.has("ma_hrm")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN ma_hrm TEXT").run();
    if (!cols.has("don_vi_id")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN don_vi_id INTEGER").run();
    if (!cols.has("modules")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN modules TEXT").run();
    if (!cols.has("lat")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN lat REAL").run();
    if (!cols.has("lng")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN lng REAL").run();
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

// ---- Phan quyen su dung module ----
// modules luu dang JSON trong cot nguoi_dung.modules. NULL = chua thiet lap
// rieng -> giu quyen cu theo vai tro (khong khoa gi them). Admin luon duoc
// phep dung moi module bat ke modules ghi gi.
const MODULE_KEYS = ["dashboard", "units", "users", "import", "config", "reports", "packages", "loginstats", "settings", "care"];
const DEFAULT_MODULES = ["dashboard", "reports", "packages", "settings"];
// Lanh dao don vi mac dinh them module Cham soc diem ban
const LEADER_MODULES = [...DEFAULT_MODULES, "care"];
function parseModules(v) {
  if (!v) return null;
  try {
    const arr = JSON.parse(v);
    if (!Array.isArray(arr)) return null;
    return arr.filter((k) => MODULE_KEYS.includes(k));
  } catch (e) { return null; }
}
function hasModule(meUser, key) {
  if (!meUser || meUser.role === "admin") return true;
  const mods = parseModules(meUser.modules);
  if (!mods) return true;
  return mods.includes(key);
}
// Quyen dung module Cham soc diem ban: chi admin hoac Lanh dao don vi
// (kem quyen module "care"; lanh dao chua thiet lap rieng thi duoc dung).
function canUseCare(meUser) {
  if (!meUser) return false;
  if (meUser.role !== "admin" && meUser.role !== "leader") return false;
  return hasModule(meUser, "care");
}
// Khoang cach (met) giua 2 toa do WGS84 theo cong thuc haversine
function haversineM(lat1, lng1, lat2, lng2) {
  const R = 6371000;
  const p1 = lat1 * Math.PI / 180, p2 = lat2 * Math.PI / 180;
  const dPhi = (lat2 - lat1) * Math.PI / 180;
  const dLam = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dPhi / 2) ** 2 + Math.cos(p1) * Math.cos(p2) * Math.sin(dLam / 2) ** 2;
  return 2 * R * Math.asin(Math.sqrt(a));
}
// Parse 1 toa do: tra {val, error}; rong -> null (khong khai bao)
function parseCoordField(v, min, max) {
  if (v === null || v === undefined || v === "") return { val: null, error: null };
  const n = Number(v);
  if (!isFinite(n) || n < min || n > max) return { val: null, error: "toa do khong hop le" };
  return { val: n, error: null };
}
// Cau lenh CTE lay cay don vi (don vi goc + moi don vi truc thuoc qua parent_id)
function unitSubtreeCTE() {
  return "WITH RECURSIVE subtree(id) AS (SELECT ? UNION ALL SELECT d.id FROM don_vi d JOIN subtree s ON d.parent_id = s.id)";
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
      { key: "ma_gd", label: "Mã GD", type: "text" },
      { key: "ma_gd_doi_tac", label: "Mã GD đối tác", type: "text" },
      { key: "ma_gd_eu", label: "Mã GD EU", type: "text" },
      { key: "thoi_gian_giao_dich", label: "Thời gian giao dịch", type: "date" },
      { key: "loai_hoa_hong", label: "Loại hoa hồng", type: "text" },
      { key: "don_vi_chi_tra", label: "Đơn vị chi trả", type: "text" },
      { key: "so_vi", label: "Số ví", type: "text" },
      { key: "vtt", label: "VTT", type: "text" },
      { key: "ttkd", label: "TTKD", type: "text" },
      { key: "loai_vi", label: "Loại ví", type: "text" },
      { key: "ho_ten", label: "Họ tên", type: "text" },
      { key: "ma_hrm_sdt_smcs", label: "Mã HRM/SĐT SMCS", type: "text" },
      { key: "ma_kenh", label: "Mã kênh", type: "text" },
      { key: "ma_hd", label: "Mã HĐ", type: "text" },
      { key: "so_tien", label: "Số tiền", type: "money" },
      { key: "mo_ta", label: "Mô tả", type: "text" },
      { key: "mo_ta_loi", label: "Mô tả lỗi", type: "text" },
      { key: "trang_thai_gd", label: "Trạng thái GD", type: "text" },
    ],
    money_col: "so_tien", time_col: "thoi_gian_giao_dich", time_fallback_col: "",
    eload_col: "", vi_col: "so_vi", sub_col: "", pkg_col: "",
    trans_col: "ma_gd", status_col: "trang_thai_gd", reason_col: "mo_ta_loi",
    // Cot khoa nghiep vu: vua la PRIMARY KEY cua bang thang (1 dong / 1 khoa),
    // vua la can cu map bao cao (doi chieu voi ma_hrm / sdt_nhan_vien cua user).
    key_col: "ma_hrm_sdt_smcs",
  },
];
async function ensureTypes(env) {
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS loai_du_lieu (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, " +
    "prefix TEXT NOT NULL, fmt TEXT NOT NULL DEFAULT 'MMYYYY', columns_json TEXT NOT NULL, " +
    "money_col TEXT, time_col TEXT, time_fallback_col TEXT, eload_col TEXT, vi_col TEXT, " +
    "sub_col TEXT, pkg_col TEXT, trans_col TEXT, status_col TEXT, reason_col TEXT, key_col TEXT, " +
    "builtin INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
  ).run();
  // CSDL cu co the chua co cot key_col (them sau) — bo sung neu thieu.
  try {
    const info = await env.DB.prepare("PRAGMA table_info(loai_du_lieu)").all();
    if (!(info.results || []).some((c) => c.name === "key_col")) {
      await env.DB.prepare("ALTER TABLE loai_du_lieu ADD COLUMN key_col TEXT").run();
    }
  } catch (e) { /* PRAGMA khong co thi bo qua, cot se duoc them o lan tao bang sau */ }
  const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM loai_du_lieu").first();
  if (c && c.n === 0) {
    for (const t of BUILTIN_TYPES) {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO loai_du_lieu (code, name, prefix, fmt, columns_json, money_col, time_col, time_fallback_col, eload_col, vi_col, sub_col, pkg_col, trans_col, status_col, reason_col, key_col, builtin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)"
      )
        .bind(t.code, t.name, t.prefix, t.fmt, JSON.stringify(t.columns), t.money_col, t.time_col, t.time_fallback_col, t.eload_col, t.vi_col, t.sub_col, t.pkg_col, t.trans_col, t.status_col, t.reason_col, t.key_col || "")
        .run();
    }
  }
  // Dong bo dinh nghia loai mac dinh (builtin) theo code moi nhat — vi du BCKH
  // doi sang dinh dang 18 truong moi. Chi cap nhat khi dinh nghia da luu khac
  // voi code (tranh ghi khong can thiet moi lan goi). Loai tu tao (builtin=0)
  // khong bi dong cham.
  for (const t of BUILTIN_TYPES) {
    const cur = await env.DB.prepare("SELECT * FROM loai_du_lieu WHERE code = ?").bind(t.code).first();
    if (!cur) {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO loai_du_lieu (code, name, prefix, fmt, columns_json, money_col, time_col, time_fallback_col, eload_col, vi_col, sub_col, pkg_col, trans_col, status_col, reason_col, key_col, builtin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)"
      )
        .bind(t.code, t.name, t.prefix, t.fmt, JSON.stringify(t.columns), t.money_col, t.time_col, t.time_fallback_col, t.eload_col, t.vi_col, t.sub_col, t.pkg_col, t.trans_col, t.status_col, t.reason_col, t.key_col || "")
        .run();
    } else if (cur.builtin) {
      const same =
        cur.name === t.name && cur.prefix === t.prefix && cur.fmt === t.fmt &&
        cur.columns_json === JSON.stringify(t.columns) &&
        (cur.money_col || "") === (t.money_col || "") && (cur.time_col || "") === (t.time_col || "") &&
        (cur.time_fallback_col || "") === (t.time_fallback_col || "") &&
        (cur.eload_col || "") === (t.eload_col || "") && (cur.vi_col || "") === (t.vi_col || "") &&
        (cur.sub_col || "") === (t.sub_col || "") && (cur.pkg_col || "") === (t.pkg_col || "") &&
        (cur.trans_col || "") === (t.trans_col || "") && (cur.status_col || "") === (t.status_col || "") &&
        (cur.reason_col || "") === (t.reason_col || "") && (cur.key_col || "") === (t.key_col || "");
      if (!same) {
        await env.DB.prepare(
          "UPDATE loai_du_lieu SET name = ?, prefix = ?, fmt = ?, columns_json = ?, money_col = ?, time_col = ?, time_fallback_col = ?, eload_col = ?, vi_col = ?, sub_col = ?, pkg_col = ?, trans_col = ?, status_col = ?, reason_col = ?, key_col = ? WHERE code = ?"
        )
          .bind(t.name, t.prefix, t.fmt, JSON.stringify(t.columns), t.money_col, t.time_col, t.time_fallback_col, t.eload_col, t.vi_col, t.sub_col, t.pkg_col, t.trans_col, t.status_col, t.reason_col, t.key_col || "", t.code)
          .run();
      }
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
  // Cot khoa nghiep vu (VD: BCKH map theo Ma HRM/SDT SMCS): doi chieu voi ca
  // ma_hrm va sdt_nhan_vien cua user vi 1 cot khoa co the chua ma HRM hoac SDT.
  if (t.key_col) {
    ownParts.push("(" + t.key_col + " = ? OR " + t.key_col + " = ?)");
    ownBinds.push(meUser.ma_hrm || "__none__", meUser.sdt_nhan_vien || "__none__");
  }
  // Loc theo don vi (danh cho Lanh dao don vi): cac giao dich cua user
  // thuoc don vi cua lanh dao VA MOI DON VI TRUC THUOC trong cay don vi
  // (don_vi.parent_id) — vi du lanh dao cap tinh thay toan tinh, lanh dao
  // cap khu vuc chi thay khu vuc do + cac don vi con cua no. Map qua
  // so_eload / so_vi trong bang nguoi_dung.
  const unitParts = [], unitBinds = [];
  if (meUser.don_vi_id) {
    const subtree = "WITH RECURSIVE subtree(id) AS (SELECT ? UNION ALL SELECT d.id FROM don_vi d JOIN subtree s ON d.parent_id = s.id)";
    if (t.eload_col) { unitParts.push(t.eload_col + " IN (" + subtree + " SELECT so_eload FROM nguoi_dung WHERE don_vi_id IN (SELECT id FROM subtree))"); unitBinds.push(meUser.don_vi_id); }
    if (t.vi_col) { unitParts.push(t.vi_col + " IN (" + subtree + " SELECT so_vi FROM nguoi_dung WHERE don_vi_id IN (SELECT id FROM subtree))"); unitBinds.push(meUser.don_vi_id); }
    if (t.key_col) {
      unitParts.push(t.key_col + " IN (" + subtree + " SELECT ma_hrm FROM nguoi_dung WHERE don_vi_id IN (SELECT id FROM subtree))"); unitBinds.push(meUser.don_vi_id);
      unitParts.push(t.key_col + " IN (" + subtree + " SELECT sdt_nhan_vien FROM nguoi_dung WHERE don_vi_id IN (SELECT id FROM subtree))"); unitBinds.push(meUser.don_vi_id);
    }
  }
  return {
    code: t.code, prefix: t.prefix, money: t.money_col, time,
    own: ownParts.length ? "(" + ownParts.join(" OR ") + ")" : "(1 = 0)",
    ownBinds,
    unit: unitParts.length ? "(" + unitParts.join(" OR ") + ")" : "(1 = 0)",
    unitBinds,
    eloadCol: t.eload_col || null, viCol: t.vi_col || null,
    subCol: t.sub_col || null, pkgCol: t.pkg_col || null,
    transCol: t.trans_col || null, statusCol: t.status_col || null, reasonCol: t.reason_col || null,
    keyCol: t.key_col || null,
  };
}
function tableNameForType(t, thang, nam) {
  const mm = String(thang).padStart(2, "0");
  return t.prefix + "_" + mm + (t.fmt === "MMYY" ? String(nam).slice(-2) : nam);
}
function createTableSQL(table, columns, pkCol) {
  if (pkCol) {
    // Loai co cot khoa nghiep vu: cot do lam PRIMARY KEY (khong co cot id tu tang).
    // Dong trung khoa se bi tu choi khi insert — phia import xu ly rieng tung dong
    // de bao ro khoa trung thay vi lam hong ca lo.
    const cols = columns.map(([n, t]) => '"' + n + '" ' + t + (n === pkCol ? " NOT NULL PRIMARY KEY" : "")).join(", ");
    return (
      'CREATE TABLE IF NOT EXISTS "' + table + '" (' +
      cols + ', imported_by TEXT, imported_at TEXT DEFAULT CURRENT_TIMESTAMP)'
    );
  }
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

// ---- Khoa bang thay the theo tung bang thang ----
// Bang khoa_bang luu quyet dinh rieng cua admin (khoa = 1, mo = 0).
// Neu chua co dong nao: mac dinh thang hien tai MO (duoc thay the),
// cac thang truoc do KHOA (chi admin moi thay the).
async function ensureTableLocks(env) {
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS khoa_bang (ten_bang TEXT PRIMARY KEY, khoa INTEGER NOT NULL DEFAULT 1, updated_by TEXT, updated_at TEXT)"
  ).run();
}
function tableMonthKey(name) {
  const m = name.match(/_(\d{2})(\d{2,4})$/);
  if (!m) return null;
  let year = parseInt(m[2], 10);
  if (m[2].length === 2) year += 2000;
  return year + "-" + m[1];
}
async function isTableLocked(env, name) {
  await ensureTableLocks(env);
  const row = await env.DB.prepare("SELECT khoa FROM khoa_bang WHERE ten_bang = ?").bind(name).first();
  if (row) return !!row.khoa;
  const mk = tableMonthKey(name);
  if (!mk) return false;
  return mk < saigonNow().slice(0, 7); // thang truoc thang hien tai: mac dinh khoa
}

// ---- Danh muc goi cuoc ----
const GOI_CUOC_CYCLES = ["1T", "3T", "6T", "12T", "18T", "24T", "36T"];
async function ensurePackages(env) {
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS goi_cuoc (id INTEGER PRIMARY KEY AUTOINCREMENT, ten_goi TEXT NOT NULL, chu_ky TEXT NOT NULL, gia_goi REAL NOT NULL DEFAULT 0, uu_dai TEXT, anh_key TEXT, noi_bat INTEGER NOT NULL DEFAULT 0, noi_bat_at TEXT, created_by TEXT, created_at TEXT DEFAULT CURRENT_TIMESTAMP, updated_at TEXT, UNIQUE(ten_goi, chu_ky))"
  ).run();
  const cols = await env.DB.prepare("PRAGMA table_info(goi_cuoc)").all();
  const names = new Set((cols.results || []).map((c) => c.name));
  if (!names.has("noi_bat")) await env.DB.prepare("ALTER TABLE goi_cuoc ADD COLUMN noi_bat INTEGER NOT NULL DEFAULT 0").run();
  if (!names.has("noi_bat_at")) await env.DB.prepare("ALTER TABLE goi_cuoc ADD COLUMN noi_bat_at TEXT").run();
}
// ---- Cham soc diem ban: dot cham soc + log cham soc (kem anh dong dau) ----
async function ensureCareTables(env) {
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS dot_cham_soc (id INTEGER PRIMARY KEY AUTOINCREMENT, ten_dot TEXT NOT NULL, ghi_chu TEXT, nguoi_tao_id INTEGER, nguoi_tao_ten TEXT, created_at TEXT)"
  ).run();
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS cham_soc (id INTEGER PRIMARY KEY AUTOINCREMENT, dot_id INTEGER NOT NULL, pos_user_id INTEGER NOT NULL, caregiver_id INTEGER, caregiver_ten TEXT, thoi_gian TEXT, lat REAL, lng REAL, khoang_cach_m REAL, anh_key TEXT, anh_thoi_gian TEXT, ghi_chu TEXT)"
  ).run();
}
async function uploadPackageImage(env, pkgId, file) {
  if (!env.ANH) throw new Error("Chua cau hinh R2 Object Storage (chua gan bucket ANH cho Worker). Xem huong dan cau hinh R2 trong module Danh muc goi cuoc.");
  const mime = file.type || "";
  if (!mime.startsWith("image/")) throw new Error("File anh phai la dinh dang anh (jpg, png, webp, gif)");
  if (file.size > 5 * 1024 * 1024) throw new Error("Anh vuot qua 5MB. Hay nen anh nho hon roi thu lai.");
  const ext = mime === "image/jpeg" ? "jpg" : mime === "image/png" ? "png" : mime === "image/webp" ? "webp" : mime === "image/gif" ? "gif" : "";
  if (!ext) throw new Error("Dinh dang anh khong duoc ho tro (chi nhan jpg, png, webp, gif)");
  const key = "goi-cuoc/" + pkgId + "-" + Date.now() + "." + ext;
  await env.ANH.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: mime } });
  return key;
}
async function readPackageForm(request) {
  const ct = request.headers.get("content-type") || "";
  if (ct.includes("multipart/form-data")) {
    const fd = await request.formData();
    const file = fd.get("anh");
    return {
      ten_goi: toText(fd.get("ten_goi")),
      chu_ky: toText(fd.get("chu_ky")),
      gia_goi: Number(fd.get("gia_goi")) || 0,
      uu_dai: toText(fd.get("uu_dai")),
      file: file && file.size > 0 ? file : null,
    };
  }
  const b = await readBody(request);
  return { ten_goi: toText(b.ten_goi), chu_ky: toText(b.chu_ky), gia_goi: Number(b.gia_goi) || 0, uu_dai: toText(b.uu_dai), file: null };
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

      // ---- Danh muc goi cuoc: cong khai, KHONG can dang nhap ----
      // (cong cu Uoc tinh tren trang chu cong khai cung dung danh muc nay)
      if (path === "/api/packages" && method === "GET") {
        await ensurePackages(env);
        const res = await env.DB.prepare("SELECT * FROM goi_cuoc ORDER BY ten_goi, chu_ky").all();
        return json({ ok: true, packages: res.results || [] });
      }

      // ---- Anh truyen thong goi cuoc: phuc vu qua Worker, KHONG can dang nhap
      // (the <img> khong gui duoc token Authorization, nen endpoint nay phai
      //  dung truoc khoi yeu cau dang nhap phia duoi)
      const imgMatch = path.match(/^\/api\/packages\/image\/(.+)$/);
      if (imgMatch && method === "GET") {
        const key = decodeURIComponent(imgMatch[1]);
        if (!/^goi-cuoc\/[A-Za-z0-9._-]+$/.test(key)) return err("Anh khong hop le", 400);
        if (!env.ANH) return err("Chua cau hinh R2 Object Storage", 501);
        const obj = await env.ANH.get(key);
        if (!obj) return err("Khong tim thay anh", 404);
        const headers = new Headers();
        obj.writeHttpMetadata(headers);
        headers.set("Cache-Control", "public, max-age=86400");
        headers.set("Access-Control-Allow-Origin", "*");
        return new Response(obj.body, { headers });
      }

      // ---- Cac API con lai deu can dang nhap ----
      await ensureUserColumns(env); // dam bao cac cot bo sung da co truoc khi truy van
      const me = await requireAuth(request, env);
      if (!me) return err("Phien dang nhap khong hop le hoac da het han. Vui long dang nhap lai.", 401);
      const isAdmin = me.role === "admin";
      const isSubAdmin = me.role === "subadmin";
      const isLeader = me.role === "leader";
      // Lanh dao don vi: xem du lieu cua cac user trong don vi cua minh VA
      // cac don vi truc thuoc (cay don_vi qua parent_id); neu chua gan don
      // vi thi tam xem du lieu cua chinh minh.
      const isUnitScoped = isLeader && !!me.don_vi_id;
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
        if (!hasModule(me, "users")) return err("Tai khoan khong co quyen su dung module Quan ly nguoi dung", 403);
        const res = await env.DB.prepare(
          "SELECT u.id, u.ma_kenh, u.ho_ten, u.username, u.role, u.so_eload, u.so_vi, u.ten_nhan_vien, u.sdt_nhan_vien, u.ma_hrm, u.don_vi_id, d.ten_don_vi AS don_vi_ten, u.can_import, u.modules, u.lat, u.lng, u.active FROM nguoi_dung u LEFT JOIN don_vi d ON d.id = u.don_vi_id ORDER BY u.ho_ten"
        ).all();
        return json({ ok: true, users: (res.results || []).map(publicUser) });
      }
      if (path === "/api/users" && method === "POST") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen tao nguoi dung", 403);
        if (!hasModule(me, "users")) return err("Tai khoan khong co quyen su dung module Quan ly nguoi dung", 403);
        const b = await readBody(request);
        if (!toText(b.ho_ten) || !toText(b.username)) return err("Thieu ho ten hoac user dang nhap", 422);
        const salt = randomSalt();
        const password = String(b.password || "Vnpt@2026");
        const hash = await hashPassword(password, salt);
        // Phan quyen: chi admin moi duoc dat loai tai khoan va cap quyen import;
        // SubAdmin tao nguoi dung thi mac dinh la user thuong, khong co quyen import.
        const newRole = isAdmin ? (b.role === "admin" ? "admin" : b.role === "subadmin" ? "subadmin" : b.role === "leader" ? "leader" : "user") : "user";
        const newCanImport = isAdmin && b.can_import ? 1 : 0;
        // Quyen module: chi admin moi duoc thiet lap; khong gui -> mac dinh
        // 4 module (Dashboard, Bao cao, Goi cuoc, Cai dat); lanh dao don vi
        // mac dinh them module Cham soc diem ban; tai khoan admin -> NULL (khong gioi han).
        let newModules = null;
        if (isAdmin && Array.isArray(b.modules)) newModules = JSON.stringify(b.modules.filter((k) => MODULE_KEYS.includes(k)));
        else if (newRole !== "admin") newModules = JSON.stringify(newRole === "leader" ? LEADER_MODULES : DEFAULT_MODULES);
        const latP = parseCoordField(b.lat, -90, 90);
        if (latP.error) return err("Vi do diem ban khong hop le (tu -90 den 90)", 422);
        const lngP = parseCoordField(b.lng, -180, 180);
        if (lngP.error) return err("Kinh do diem ban khong hop le (tu -180 den 180)", 422);
        const r = await env.DB.prepare(
          "INSERT INTO nguoi_dung (ma_kenh, ho_ten, username, password_hash, salt, role, so_eload, so_vi, ten_nhan_vien, sdt_nhan_vien, ma_hrm, don_vi_id, can_import, modules, lat, lng) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
          .bind(
            toText(b.ma_kenh), toText(b.ho_ten), toText(b.username), hash, salt,
            newRole,
            toText(b.so_eload), toText(b.so_vi), toText(b.ten_nhan_vien), toText(b.sdt_nhan_vien), toText(b.ma_hrm),
            b.don_vi_id ? Number(b.don_vi_id) : null, newCanImport, newModules, latP.val, lngP.val
          )
          .run();
        return json({ ok: true, id: r.meta.last_row_id });
      }
      // ---- Import nguoi dung tu Excel ----
      if (path === "/api/users/import" && method === "POST") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen import nguoi dung", 403);
        if (!hasModule(me, "users")) return err("Tai khoan khong co quyen su dung module Quan ly nguoi dung", 403);
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
          const impRole = isAdmin ? (r.role === "admin" ? "admin" : r.role === "subadmin" ? "subadmin" : r.role === "leader" ? "leader" : "user") : "user";
          // Toa do: khong hop le thi de trong + bao lai (khong bo dong)
          let impLat = null, impLng = null;
          const impLatP = parseCoordField(r.lat, -90, 90);
          const impLngP = parseCoordField(r.lng, -180, 180);
          if (impLatP.error) warnings.push({ row: i + 2, reason: "Vi do khong hop le — da de trong" });
          else impLat = impLatP.val;
          if (impLngP.error) warnings.push({ row: i + 2, reason: "Kinh do khong hop le — da de trong" });
          else impLng = impLngP.val;
          await env.DB.prepare(
            "INSERT INTO nguoi_dung (ma_kenh, ho_ten, username, password_hash, salt, role, so_eload, so_vi, ten_nhan_vien, sdt_nhan_vien, ma_hrm, don_vi_id, can_import, modules, lat, lng) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
          )
            .bind(
              toText(r.ma_kenh), hoTen, username, hash, salt,
              impRole,
              toText(r.so_eload), toText(r.so_vi), toText(r.ten_nhan_vien), toText(r.sdt_nhan_vien), toText(r.ma_hrm), donViId, isAdmin && r.can_import ? 1 : 0,
              impRole === "admin" ? null : JSON.stringify(impRole === "leader" ? LEADER_MODULES : DEFAULT_MODULES),
              impLat, impLng
            )
            .run();
          created++;
        }
        return json({ ok: true, created, skipped, errors: errors.slice(0, 50), warnings: warnings.slice(0, 50) });
      }
      const userMatch = path.match(/^\/api\/users\/(\d+)$/);
      if (userMatch && method === "PUT") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen sua nguoi dung", 403);
        if (!hasModule(me, "users")) return err("Tai khoan khong co quyen su dung module Quan ly nguoi dung", 403);
        const b = await readBody(request);
        // Phan quyen: SubAdmin khong duoc thay doi loai tai khoan, quyen import
        // va quyen module cua nguoi dung -> giu nguyen gia tri dang co trong CSDL.
        let newRole = b.role === "admin" ? "admin" : b.role === "subadmin" ? "subadmin" : b.role === "leader" ? "leader" : "user";
        let newCanImport = b.can_import ? 1 : 0;
        let newModules;
        if (!isAdmin) {
          const cur = await env.DB.prepare("SELECT role, can_import, modules FROM nguoi_dung WHERE id = ?").bind(Number(userMatch[1])).first();
          if (cur) { newRole = cur.role; newCanImport = cur.can_import; newModules = cur.modules; }
          else newModules = null;
        } else if (Array.isArray(b.modules)) {
          newModules = JSON.stringify(b.modules.filter((k) => MODULE_KEYS.includes(k)));
        } else {
          const cur = await env.DB.prepare("SELECT modules FROM nguoi_dung WHERE id = ?").bind(Number(userMatch[1])).first();
          newModules = cur ? cur.modules : null;
        }
        const latP = parseCoordField(b.lat, -90, 90);
        if (latP.error) return err("Vi do diem ban khong hop le (tu -90 den 90)", 422);
        const lngP = parseCoordField(b.lng, -180, 180);
        if (lngP.error) return err("Kinh do diem ban khong hop le (tu -180 den 180)", 422);
        await env.DB.prepare(
          "UPDATE nguoi_dung SET ma_kenh = ?, ho_ten = ?, so_eload = ?, so_vi = ?, ten_nhan_vien = ?, sdt_nhan_vien = ?, ma_hrm = ?, don_vi_id = ?, can_import = ?, role = ?, modules = ?, lat = ?, lng = ?, active = ? WHERE id = ?"
        )
          .bind(
            toText(b.ma_kenh), toText(b.ho_ten), toText(b.so_eload), toText(b.so_vi),
            toText(b.ten_nhan_vien), toText(b.sdt_nhan_vien), toText(b.ma_hrm), b.don_vi_id ? Number(b.don_vi_id) : null,
            newCanImport, newRole, newModules, latP.val, lngP.val,
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
        if (!hasModule(me, "users")) return err("Tai khoan khong co quyen su dung module Quan ly nguoi dung", 403);
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
        for (const rc of ["time_fallback_col", "vi_col", "sub_col", "pkg_col", "trans_col", "status_col", "reason_col", "key_col"]) {
          if (b[rc] && !keys.has(b[rc])) return err("Cot vai tro khong nam trong danh sach cot: " + rc, 422);
        }
        const exists = (await getDataTypes(env)).some((t) => t.code === code || t.prefix === code);
        if (exists) return err("Ma loai du lieu da ton tai: " + code, 422);
        const cleanCols = columns.map((c) => ({
          key: String(c.key), label: toText(c.label) || String(c.key),
          type: ["money", "number", "date"].includes(c.type) ? c.type : "text",
        }));
        const r = await env.DB.prepare(
          "INSERT INTO loai_du_lieu (code, name, prefix, fmt, columns_json, money_col, time_col, time_fallback_col, eload_col, vi_col, sub_col, pkg_col, trans_col, status_col, reason_col, key_col, builtin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)"
        )
          .bind(code, name, code, fmt, JSON.stringify(cleanCols),
            b.money_col, b.time_col, b.time_fallback_col || "", b.eload_col, b.vi_col || "",
            b.sub_col || "", b.pkg_col || "", b.trans_col || "", b.status_col || "", b.reason_col || "", b.key_col || "")
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
        if (!hasModule(me, "import")) return err("Tai khoan khong co quyen su dung module Quan ly du lieu dau vao", 403);
        const types = await getDataTypes(env);
        const out = [];
        for (const t of types) {
          const tables = await listMonthlyTables(env, t.prefix);
          for (const name of tables) {
            const c = await env.DB.prepare('SELECT COUNT(*) AS n FROM "' + name + '"').first();
            out.push({ table: name, code: t.code, rows: c ? c.n : 0, locked: await isTableLocked(env, name) });
          }
        }
        return json({ ok: true, tables: out });
      }
      // ---- Xoa bang du lieu da import ----
      const tblMatch = path.match(/^\/api\/import\/tables\/([A-Za-z0-9_]+)$/);
      if (tblMatch && method === "DELETE") {
        if (!hasModule(me, "import")) return err("Tai khoan khong co quyen su dung module Quan ly du lieu dau vao", 403);
        if (!isAdmin && (isSubAdmin || !me.can_import)) return err("Tai khoan khong co quyen xoa bang du lieu (SubAdmin khong duoc phep xoa bang)", 403);
        const name = tblMatch[1];
        const types = await getDataTypes(env);
        const okName = types.some((t) => new RegExp("^" + t.prefix + "_\\d{4,6}$").test(name));
        if (!okName) return err("Ten bang khong hop le", 422);
        await env.DB.prepare('DROP TABLE IF EXISTS "' + name + '"').run();
        return json({ ok: true, table: name });
      }
      // ---- Trang thai khoa thay the cua 1 bang thang ----
      if (path === "/api/import/table-lock" && method === "GET") {
        if (!hasModule(me, "import")) return err("Tai khoan khong co quyen su dung module Quan ly du lieu dau vao", 403);
        const name = url.searchParams.get("table") || "";
        if (!name) return err("Thieu ten bang", 422);
        const locked = await isTableLocked(env, name);
        return json({ ok: true, table: name, locked, can_replace: isAdmin || !locked });
      }
      // ---- Admin khoa / mo khoa thay the cho 1 bang thang ----
      if (path === "/api/table-locks" && method === "POST") {
        if (!isAdmin) return err("Chi admin moi co quyen khoa/mo khoa bang du lieu", 403);
        const b = await readBody(request);
        const name = toText(b.table);
        if (!name) return err("Thieu ten bang", 422);
        await ensureTableLocks(env);
        await env.DB.prepare(
          "INSERT INTO khoa_bang (ten_bang, khoa, updated_by, updated_at) VALUES (?, ?, ?, ?) ON CONFLICT(ten_bang) DO UPDATE SET khoa = excluded.khoa, updated_by = excluded.updated_by, updated_at = excluded.updated_at"
        )
          .bind(name, b.locked ? 1 : 0, me.username, saigonNow())
          .run();
        return json({ ok: true, table: name, locked: !!b.locked });
      }
      if (path === "/api/import" && method === "POST") {
        if (!isAdmin && !me.can_import) return err("Tai khoan khong co quyen import du lieu", 403);
        if (!hasModule(me, "import")) return err("Tai khoan khong co quyen su dung module Quan ly du lieu dau vao", 403);
        const b = await readBody(request);
        const types = await getDataTypes(env);
        const dtype = types.find((t) => t.code === String(b.loai || "").toUpperCase());
        if (!dtype) return err("Loai du lieu khong ton tai: " + (b.loai || ""), 422);
        const mode = b.mode === "replace" ? "replace" : b.mode === "create" ? "create" : "append"; // append = Cap nhat, replace = Thay the, create = Tao moi
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
        // Phan quyen thay the theo tung bang: admin luon duoc phep; user co quyen
        // import chi duoc thay the khi bang KHONG bi khoa (mac dinh: thang hien
        // tai mo, cac thang truoc do khoa tru khi admin mo khoa).
        if (mode === "replace" && !isAdmin) {
          const locked = await isTableLocked(env, table);
          if (locked) return err("Bang du lieu " + table + " dang bi khoa thay the. Chi admin moi duoc thay the du lieu cua bang nay. Lien he admin de mo khoa neu can.", 403);
        }
        if (mode === "create") {
          // Che do Tao moi: chi import khi bang thang nay chua ton tai,
          // tranh import trung lam nhan doi so lieu.
          const ex = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name = ?").bind(table).first();
          if (ex) return err("Bang du lieu " + table + " da ton tai. Hay dung che do 'Cap nhat' de nap them du lieu, hoac 'Thay the' de xoa du lieu cu va nap lai tu dau.", 409);
        }
        if (mode === "replace") {
          await env.DB.prepare('DROP TABLE IF EXISTS "' + table + '"').run();
        }
        await env.DB.prepare(createTableSQL(table, columns, dtype.key_col || "")).run();
        const numericCols = new Set(columns.filter(([, t]) => t === "REAL").map(([n]) => n));
        const sql =
          'INSERT INTO "' + table + '" (' + colNames.map((n) => '"' + n + '"').join(", ") +
          ", imported_by) VALUES (" + colNames.map(() => "?").join(", ") + ", ?)";
        const pkIdx = dtype.key_col ? colNames.indexOf(dtype.key_col) : -1;
        let inserted = 0, skipped = 0;
        const errors = [];
        const CHUNK = 100;
        for (let i = 0; i < rows.length; i += CHUNK) {
          const valsList = rows.slice(i, i + CHUNK).map((row) => {
            const vals = colNames.map((n) => {
              const v = row[n];
              return numericCols.has(n) ? toNumber(v) : toText(v);
            });
            vals.push(me.username);
            return vals;
          });
          try {
            await env.DB.batch(valsList.map((vals) => env.DB.prepare(sql).bind(...vals)));
            inserted += valsList.length;
          } catch (e) {
            // 1 dong loi (VD: trung khoa chinh) khong duoc lam hong ca lo 100 dong:
            // chen lai tung dong, dong loi thi bo qua co bao cao.
            for (const vals of valsList) {
              try { await env.DB.prepare(sql).bind(...vals).run(); inserted++; }
              catch (e2) {
                skipped++;
                if (errors.length < 50) {
                  errors.push(pkIdx >= 0 && vals[pkIdx]
                    ? ("Trùng khóa chính " + dtype.key_col + ": " + vals[pkIdx])
                    : String((e2 && e2.message) || e2).slice(0, 120));
                }
              }
            }
          }
        }
        return json({ ok: true, table, inserted, skipped, errors, mode });
      }

      // ---- Bao cao thong ke ----
      if (path === "/api/reports/summary" && method === "GET") {
        if (!hasModule(me, "reports") && !hasModule(me, "dashboard")) return err("Tai khoan khong co quyen xem bao cao", 403);
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
        // Bang thang cu khong khop dinh nghia moi (thieu cot) thi bo qua co bao cao,
        // thay vi lam hong toan bo bao cao — VD: bang BCKH thang cu theo mau cu.
        const skippedTables = [];
        for (const s of sources) {
          const tables = await listMonthlyTables(env, s.prefix);
          for (const t of tables) {
            if (!tableInRange(t, s.prefix, from, to)) continue;
            const innerCols = [s.time + " AS tg", s.money + " AS tien"];
            if (s.eloadCol) innerCols.push(s.eloadCol);
            if (s.viCol) innerCols.push(s.viCol);
            if (s.keyCol) innerCols.push(s.keyCol);
            let sql =
              'SELECT ' + groupExpr + ' AS ky, COUNT(*) AS so_giao_dich, COALESCE(SUM(tien), 0) AS tong_tien FROM (SELECT ' +
              innerCols.join(", ") + ' FROM "' + t + '") WHERE substr(tg, 1, 10) BETWEEN ? AND ?';
            const localBinds = [from, to];
            if (!isPrivileged) {
              if (isUnitScoped) { sql += " AND " + s.unit; localBinds.push(...s.unitBinds); }
              else { sql += " AND " + s.own; localBinds.push(...s.ownBinds); }
            }
            sql += " GROUP BY ky";
            let res;
            try { res = await env.DB.prepare(sql).bind(...localBinds).all(); }
            catch (e) { skippedTables.push(t); continue; }
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
          skipped_tables: skippedTables,
        });
      }
      if (path === "/api/reports/detail" && method === "GET") {
        if (!hasModule(me, "reports")) return err("Tai khoan khong co quyen xem bao cao", 403);
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        const loai = (url.searchParams.get("loai") || "ALL").toUpperCase();
        const limit = Math.min(Number(url.searchParams.get("limit") || 500), 2000);
        const out = [];
        const skippedTables = [];
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
              if (isUnitScoped) { sql += " AND " + s.unit; binds.push(...s.unitBinds); }
              else { sql += " AND " + s.own; binds.push(...s.ownBinds); }
            }
            sql += " ORDER BY thoi_gian DESC LIMIT ?";
            binds.push(limit);
            let res;
            try { res = await env.DB.prepare(sql).bind(...binds).all(); }
            catch (e) { skippedTables.push(t); continue; }
            out.push(...(res.results || []));
          }
        }
        out.sort((a, b) => String(b.thoi_gian || "").localeCompare(String(a.thoi_gian || "")));
        return json({ ok: true, rows: out.slice(0, limit), skipped_tables: skippedTables });
      }

      // ---- Thong ke dang nhap theo thang (admin & subadmin) ----
      if (path === "/api/login-stats" && method === "GET") {
        if (!isPrivileged) return err("Chi admin/subadmin moi co quyen xem thong ke dang nhap", 403);
        if (!hasModule(me, "loginstats")) return err("Tai khoan khong co quyen su dung module Thong ke dang nhap", 403);
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

      // ---- Danh muc goi cuoc ----
      if (path === "/api/packages" && method === "POST") {
        if (!isAdmin) return err("Chi admin moi co quyen them goi cuoc", 403);
        await ensurePackages(env);
        const f = await readPackageForm(request);
        if (!f.ten_goi) return err("Thieu ten goi cuoc", 422);
        if (!GOI_CUOC_CYCLES.includes(f.chu_ky)) return err("Chu ky goi khong hop le (chi nhan 1T, 3T, 6T, 12T, 18T, 24T, 36T)", 422);
        const dup = await env.DB.prepare("SELECT id FROM goi_cuoc WHERE ten_goi = ? AND chu_ky = ?").bind(f.ten_goi, f.chu_ky).first();
        if (dup) return err("Goi cuoc '" + f.ten_goi + "' chu ky " + f.chu_ky + " da ton tai", 409);
        const r = await env.DB.prepare(
          "INSERT INTO goi_cuoc (ten_goi, chu_ky, gia_goi, uu_dai, created_by) VALUES (?, ?, ?, ?, ?)"
        )
          .bind(f.ten_goi, f.chu_ky, f.gia_goi, f.uu_dai, me.username)
          .run();
        const id = r.meta.last_row_id;
        if (f.file) {
          const key = await uploadPackageImage(env, id, f.file);
          // Anh dung chung theo TEN GOI: cap nhat cho moi chu ky cung ten,
          // dong thoi xoa cac anh cu cua ten goi nay khoi R2.
          const olds = await env.DB.prepare("SELECT DISTINCT anh_key FROM goi_cuoc WHERE ten_goi = ? AND anh_key IS NOT NULL").bind(f.ten_goi).all();
          await env.DB.prepare("UPDATE goi_cuoc SET anh_key = ? WHERE ten_goi = ?").bind(key, f.ten_goi).run();
          if (env.ANH) for (const o of olds.results || []) { if (o.anh_key !== key) { try { await env.ANH.delete(o.anh_key); } catch (e) { /* bo qua */ } } }
        } else {
          // Khong tai anh moi: ke thua anh chung cua ten goi neu da co
          const ex = await env.DB.prepare("SELECT anh_key FROM goi_cuoc WHERE ten_goi = ? AND anh_key IS NOT NULL LIMIT 1").bind(f.ten_goi).first();
          if (ex) await env.DB.prepare("UPDATE goi_cuoc SET anh_key = ? WHERE id = ?").bind(ex.anh_key, id).run();
        }
        return json({ ok: true, id });
      }
      const pkgMatch = path.match(/^\/api\/packages\/(\d+)$/);
      if (pkgMatch && method === "PUT") {
        if (!isAdmin) return err("Chi admin moi co quyen sua goi cuoc", 403);
        await ensurePackages(env);
        const id = Number(pkgMatch[1]);
        const cur = await env.DB.prepare("SELECT * FROM goi_cuoc WHERE id = ?").bind(id).first();
        if (!cur) return err("Khong tim thay goi cuoc", 404);
        const f = await readPackageForm(request);
        if (!f.ten_goi) return err("Thieu ten goi cuoc", 422);
        if (!GOI_CUOC_CYCLES.includes(f.chu_ky)) return err("Chu ky goi khong hop le (chi nhan 1T, 3T, 6T, 12T, 18T, 24T, 36T)", 422);
        const dup = await env.DB.prepare("SELECT id FROM goi_cuoc WHERE ten_goi = ? AND chu_ky = ? AND id != ?").bind(f.ten_goi, f.chu_ky, id).first();
        if (dup) return err("Goi cuoc '" + f.ten_goi + "' chu ky " + f.chu_ky + " da ton tai", 409);
        let anhKey = cur.anh_key;
        if (f.file) {
          const key = await uploadPackageImage(env, id, f.file);
          // Anh dung chung theo TEN GOI: chi ap dung khi ten goi khong doi;
          // neu doi ten thi anh moi chi gan cho dong nay.
          if (f.ten_goi === cur.ten_goi) {
            const olds = await env.DB.prepare("SELECT DISTINCT anh_key FROM goi_cuoc WHERE ten_goi = ? AND anh_key IS NOT NULL").bind(f.ten_goi).all();
            await env.DB.prepare("UPDATE goi_cuoc SET anh_key = ? WHERE ten_goi = ?").bind(key, f.ten_goi).run();
            if (env.ANH) for (const o of olds.results || []) { if (o.anh_key !== key) { try { await env.ANH.delete(o.anh_key); } catch (e) { /* bo qua */ } } }
          }
          anhKey = key;
        }
        await env.DB.prepare(
          "UPDATE goi_cuoc SET ten_goi = ?, chu_ky = ?, gia_goi = ?, uu_dai = ?, anh_key = ?, updated_at = ? WHERE id = ?"
        )
          .bind(f.ten_goi, f.chu_ky, f.gia_goi, f.uu_dai, anhKey, saigonNow(), id)
          .run();
        return json({ ok: true, id });
      }
      if (pkgMatch && method === "DELETE") {
        if (!isAdmin) return err("Chi admin moi co quyen xoa goi cuoc", 403);
        await ensurePackages(env);
        const id = Number(pkgMatch[1]);
        const cur = await env.DB.prepare("SELECT anh_key FROM goi_cuoc WHERE id = ?").bind(id).first();
        await env.DB.prepare("DELETE FROM goi_cuoc WHERE id = ?").bind(id).run();
        // Anh dung chung theo ten goi: chi xoa file tren R2 khi khong con
        // dong nao tham chieu toi anh_key nay.
        if (cur && cur.anh_key && env.ANH) {
          const ref = await env.DB.prepare("SELECT COUNT(*) AS n FROM goi_cuoc WHERE anh_key = ?").bind(cur.anh_key).first();
          if (!ref || ref.n === 0) { try { await env.ANH.delete(cur.anh_key); } catch (e) { /* bo qua */ } }
        }
        return json({ ok: true });
      }
      // ---- Admin ghim / bo ghim goi cuoc len top 5 hien thi ----
      const nbMatch = path.match(/^\/api\/packages\/(\d+)\/noi-bat$/);
      if (nbMatch && method === "POST") {
        if (!isAdmin) return err("Chi admin moi co quyen ghim goi cuoc hien thi", 403);
        await ensurePackages(env);
        const id = Number(nbMatch[1]);
        const b = await readBody(request);
        const want = !!b.noi_bat;
        const cur = await env.DB.prepare("SELECT noi_bat FROM goi_cuoc WHERE id = ?").bind(id).first();
        if (!cur) return err("Khong tim thay goi cuoc", 404);
        if (want && !cur.noi_bat) {
          const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM goi_cuoc WHERE noi_bat = 1").first();
          if (c && c.n >= 5) return err("Da du 5 goi cuoc hien thi. Hay bo ghim 1 goi truoc khi ghim goi moi.", 409);
        }
        await env.DB.prepare("UPDATE goi_cuoc SET noi_bat = ?, noi_bat_at = ? WHERE id = ?").bind(want ? 1 : 0, want ? saigonNow() : null, id).run();
        return json({ ok: true, id, noi_bat: want });
      }
      if (path === "/api/packages/import" && method === "POST") {
        if (!isAdmin) return err("Chi admin moi co quyen import danh sach goi cuoc", 403);
        await ensurePackages(env);
        const b = await readBody(request);
        const rows = Array.isArray(b.rows) ? b.rows : [];
        let created = 0, skipped = 0;
        const errors = [];
        for (let i = 0; i < rows.length; i++) {
          const r = rows[i] || {};
          const tenGoi = toText(r.ten_goi);
          const chuKy = toText(r.chu_ky).toUpperCase();
          const giaGoi = Number(r.gia_goi) || 0;
          if (!tenGoi) { skipped++; errors.push({ row: i + 2, reason: "Thieu Ten goi cuoc" }); continue; }
          if (!GOI_CUOC_CYCLES.includes(chuKy)) { skipped++; errors.push({ row: i + 2, reason: "Chu ky khong hop le: " + (r.chu_ky || "") }); continue; }
          const dup = await env.DB.prepare("SELECT id FROM goi_cuoc WHERE ten_goi = ? AND chu_ky = ?").bind(tenGoi, chuKy).first();
          if (dup) { skipped++; errors.push({ row: i + 2, reason: "Goi cuoc da ton tai: " + tenGoi + " (" + chuKy + ")" }); continue; }
          // Dong moi ke thua anh chung cua ten goi neu da co
          const exKey = await env.DB.prepare("SELECT anh_key FROM goi_cuoc WHERE ten_goi = ? AND anh_key IS NOT NULL LIMIT 1").bind(tenGoi).first();
          await env.DB.prepare(
            "INSERT INTO goi_cuoc (ten_goi, chu_ky, gia_goi, uu_dai, anh_key, created_by) VALUES (?, ?, ?, ?, ?, ?)"
          )
            .bind(tenGoi, chuKy, giaGoi, toText(r.uu_dai), exKey ? exKey.anh_key : null, me.username)
            .run();
          created++;
        }
        return json({ ok: true, created, skipped, errors: errors.slice(0, 50) });
      }

      // ---- Cham soc diem ban (admin & Lanh dao don vi) ----
      if (path === "/api/care/batches" && method === "GET") {
        if (!canUseCare(me)) return err("Chi Lanh dao don vi moi co quyen su dung module Cham soc diem ban", 403);
        await ensureCareTables(env);
        const counts = "(SELECT COUNT(*) FROM cham_soc c WHERE c.dot_id = d.id) AS so_luot, (SELECT COUNT(DISTINCT c.pos_user_id) FROM cham_soc c WHERE c.dot_id = d.id) AS so_diem";
        let res;
        if (isAdmin) {
          res = await env.DB.prepare("SELECT d.*, " + counts + " FROM dot_cham_soc d ORDER BY d.id DESC").all();
        } else {
          // Lanh dao chi thay dot do minh tao + dot do admin tao (nguoi tao co role admin hien tai);
          // khong thay dot cua lanh dao khac tao.
          res = await env.DB.prepare("SELECT d.*, " + counts + " FROM dot_cham_soc d LEFT JOIN nguoi_dung u ON u.id = d.nguoi_tao_id WHERE d.nguoi_tao_id = ? OR u.role = 'admin' ORDER BY d.id DESC").bind(me.id).all();
        }
        return json({ ok: true, batches: res.results || [] });
      }
      if (path === "/api/care/batches" && method === "POST") {
        if (!canUseCare(me)) return err("Chi Lanh dao don vi moi co quyen su dung module Cham soc diem ban", 403);
        await ensureCareTables(env);
        const b = await readBody(request);
        if (!toText(b.ten_dot)) return err("Thieu ten dot cham soc", 422);
        const r = await env.DB.prepare(
          "INSERT INTO dot_cham_soc (ten_dot, ghi_chu, nguoi_tao_id, nguoi_tao_ten, created_at) VALUES (?, ?, ?, ?, ?)"
        ).bind(toText(b.ten_dot), toText(b.ghi_chu), me.id, me.ho_ten, saigonNow()).run();
        return json({ ok: true, id: r.meta.last_row_id });
      }
      const careBatchMatch = path.match(/^\/api\/care\/batches\/(\d+)$/);
      if (careBatchMatch && method === "DELETE") {
        if (!canUseCare(me)) return err("Chi Lanh dao don vi moi co quyen su dung module Cham soc diem ban", 403);
        await ensureCareTables(env);
        const batch = await env.DB.prepare("SELECT * FROM dot_cham_soc WHERE id = ?").bind(Number(careBatchMatch[1])).first();
        if (!batch) return err("Khong tim thay dot cham soc", 404);
        // Admin xoa duoc dot cua moi user; user thuong chi xoa duoc dot do chinh minh tao.
        if (!isAdmin && batch.nguoi_tao_id !== me.id) return err("Ban chi duoc xoa dot cham soc do chinh minh tao", 403);
        // Xoa anh R2 cua cac luot cham soc trong dot (co gang het suc, loi thi bo qua),
        // roi xoa luot cham soc va dot.
        if (env.ANH) {
          const keys = await env.DB.prepare("SELECT anh_key FROM cham_soc WHERE dot_id = ? AND anh_key IS NOT NULL").bind(batch.id).all();
          for (const row of (keys.results || [])) { try { await env.ANH.delete(row.anh_key); } catch (e) { /* bo qua */ } }
        }
        const del = await env.DB.prepare("DELETE FROM cham_soc WHERE dot_id = ?").bind(batch.id).run();
        await env.DB.prepare("DELETE FROM dot_cham_soc WHERE id = ?").bind(batch.id).run();
        return json({ ok: true, deleted_records: del.meta ? del.meta.changes : 0 });
      }
      // Diem ban trong ban kinh 20m quanh vi tri thiet bi (khong co vi tri -> khong tra diem nao)
      if (path === "/api/care/nearby" && method === "GET") {
        if (!canUseCare(me)) return err("Chi Lanh dao don vi moi co quyen su dung module Cham soc diem ban", 403);
        await ensureCareTables(env);
        const lat = Number(url.searchParams.get("lat"));
        const lng = Number(url.searchParams.get("lng"));
        if (!isFinite(lat) || !isFinite(lng)) return json({ ok: true, pos: [], reason: "no_location" });
        if (isLeader && !me.don_vi_id) return json({ ok: true, pos: [], reason: "no_unit" });
        const base = "SELECT u.id, u.ho_ten, u.ma_kenh, u.lat, u.lng, u.don_vi_id, d.ten_don_vi AS don_vi_ten FROM nguoi_dung u LEFT JOIN don_vi d ON d.id = u.don_vi_id WHERE u.role = 'user' AND u.active = 1 AND u.lat IS NOT NULL AND u.lng IS NOT NULL";
        let rows;
        if (isAdmin) {
          rows = (await env.DB.prepare(base).all()).results || [];
        } else {
          rows = (await env.DB.prepare(unitSubtreeCTE() + " " + base + " AND u.don_vi_id IN (SELECT id FROM subtree)").bind(me.don_vi_id).all()).results || [];
        }
        const pos = rows
          .map((u) => ({ id: u.id, ho_ten: u.ho_ten, ma_kenh: u.ma_kenh, lat: u.lat, lng: u.lng, don_vi_ten: u.don_vi_ten, khoang_cach_m: Math.round(haversineM(lat, lng, u.lat, u.lng) * 10) / 10 }))
          .filter((u) => u.khoang_cach_m <= 20)
          .sort((a, b) => a.khoang_cach_m - b.khoang_cach_m)
          .slice(0, 100);
        return json({ ok: true, pos });
      }
      // Ghi nhan cham soc: bat buoc co anh (anh da dong dau toa do + thoi gian chup o client)
      if (path === "/api/care/records" && method === "POST") {
        if (!canUseCare(me)) return err("Chi Lanh dao don vi moi co quyen su dung module Cham soc diem ban", 403);
        await ensureCareTables(env);
        const ct = request.headers.get("content-type") || "";
        if (!ct.includes("multipart/form-data")) return err("Du lieu gui len phai la multipart", 422);
        const fd = await request.formData();
        const dotId = Number(fd.get("dot_id"));
        const posId = Number(fd.get("pos_user_id"));
        const lat = Number(fd.get("lat"));
        const lng = Number(fd.get("lng"));
        const photoTime = toText(fd.get("photo_time"));
        const ghiChu = toText(fd.get("ghi_chu"));
        const file = fd.get("anh");
        if (!dotId || !posId) return err("Thieu dot cham soc hoac diem ban", 422);
        if (!isFinite(lat) || !isFinite(lng)) return err("Thieu vi tri chup anh", 422);
        if (!file || !file.size) return err("Chua co anh diem ban", 422);
        const dot = await env.DB.prepare("SELECT id FROM dot_cham_soc WHERE id = ?").bind(dotId).first();
        if (!dot) return err("Khong tim thay dot cham soc", 404);
        const pos = await env.DB.prepare("SELECT id, ho_ten, don_vi_id, lat, lng FROM nguoi_dung WHERE id = ? AND role = 'user'").bind(posId).first();
        if (!pos || pos.lat === null || pos.lng === null) return err("Diem ban khong co toa do khai bao", 422);
        if (isLeader) {
          const inScope = await env.DB.prepare(unitSubtreeCTE() + " SELECT 1 FROM nguoi_dung WHERE id = ? AND don_vi_id IN (SELECT id FROM subtree)").bind(me.don_vi_id, posId).first();
          if (!inScope) return err("Diem ban khong thuoc pham vi don vi cua ban", 403);
        }
        const dist = haversineM(lat, lng, pos.lat, pos.lng);
        if (dist > 20) return err("Vi tri chup anh cach diem ban " + (Math.round(dist * 10) / 10) + "m, vuot qua ban kinh 20m cho phep", 403);
        if (!env.ANH) return err("Chua cau hinh R2 Object Storage (chua gan bucket ANH cho Worker)", 501);
        const mime = file.type || "";
        if (!mime.startsWith("image/")) return err("File anh phai la dinh dang anh", 422);
        if (file.size > 5 * 1024 * 1024) return err("Anh vuot qua 5MB", 422);
        const ext = mime === "image/jpeg" ? "jpg" : mime === "image/png" ? "png" : mime === "image/webp" ? "webp" : mime === "image/gif" ? "gif" : "";
        if (!ext) return err("Dinh dang anh khong duoc ho tro (chi nhan jpg, png, webp, gif)", 422);
        const key = "cham-soc/" + posId + "-" + Date.now() + "." + ext;
        await env.ANH.put(key, await file.arrayBuffer(), { httpMetadata: { contentType: mime } });
        const r = await env.DB.prepare(
          "INSERT INTO cham_soc (dot_id, pos_user_id, caregiver_id, caregiver_ten, thoi_gian, lat, lng, khoang_cach_m, anh_key, anh_thoi_gian, ghi_chu) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        ).bind(dotId, posId, me.id, me.ho_ten, saigonNow(), lat, lng, Math.round(dist * 10) / 10, key, photoTime || null, ghiChu).run();
        return json({ ok: true, id: r.meta.last_row_id, khoang_cach_m: Math.round(dist * 10) / 10 });
      }
      if (path === "/api/care/records" && method === "GET") {
        if (!canUseCare(me)) return err("Chi Lanh dao don vi moi co quyen su dung module Cham soc diem ban", 403);
        await ensureCareTables(env);
        const dotId = url.searchParams.get("dot_id");
        if (dotId && !isAdmin) {
          // Chan xem lich su cua dot khong thuoc pham vi nhin thay (dot cua lanh dao khac).
          const batch = await env.DB.prepare("SELECT d.nguoi_tao_id, u.role AS creator_role FROM dot_cham_soc d LEFT JOIN nguoi_dung u ON u.id = d.nguoi_tao_id WHERE d.id = ?").bind(Number(dotId)).first();
          if (batch && batch.nguoi_tao_id !== me.id && batch.creator_role !== "admin") return err("Ban khong co quyen xem dot cham soc nay", 403);
        }
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        const limit = Math.min(1000, Number(url.searchParams.get("limit")) || 200);
        const base = "SELECT c.*, p.ho_ten AS pos_ten, p.ma_kenh AS pos_ma, d.ten_don_vi AS don_vi_ten, dt.ten_dot FROM cham_soc c JOIN nguoi_dung p ON p.id = c.pos_user_id LEFT JOIN don_vi d ON d.id = p.don_vi_id LEFT JOIN dot_cham_soc dt ON dt.id = c.dot_id WHERE substr(c.thoi_gian, 1, 10) BETWEEN ? AND ?";
        let sql = base;
        let binds = [from, to];
        if (dotId) { sql += " AND c.dot_id = ?"; binds.push(Number(dotId)); }
        if (isLeader) {
          sql = unitSubtreeCTE() + " " + sql + " AND p.don_vi_id IN (SELECT id FROM subtree)";
          binds = [me.don_vi_id, ...binds];
        }
        sql += " ORDER BY c.thoi_gian DESC LIMIT ?";
        binds.push(limit);
        const res = await env.DB.prepare(sql).bind(...binds).all();
        return json({ ok: true, records: res.results || [] });
      }
      // Xem anh cham soc (xac thuc + dung pham vi; anh khong phuc vu cong khai nhu anh goi cuoc)
      const careImgMatch = path.match(/^\/api\/care\/records\/(\d+)\/image$/);
      if (careImgMatch && method === "GET") {
        if (!hasModule(me, "care") && !hasModule(me, "reports")) return err("Tai khoan khong co quyen xem anh cham soc", 403);
        await ensureCareTables(env);
        const rec = await env.DB.prepare("SELECT c.*, p.don_vi_id AS pos_don_vi FROM cham_soc c JOIN nguoi_dung p ON p.id = c.pos_user_id WHERE c.id = ?").bind(Number(careImgMatch[1])).first();
        if (!rec || !rec.anh_key) return err("Khong tim thay anh", 404);
        if (!isPrivileged) {
          let allowed = rec.caregiver_id === me.id;
          if (!allowed && isLeader && me.don_vi_id) {
            const ok = await env.DB.prepare(unitSubtreeCTE() + " SELECT 1 FROM nguoi_dung WHERE id = ? AND don_vi_id IN (SELECT id FROM subtree)").bind(me.don_vi_id, rec.pos_user_id).first();
            allowed = !!ok;
          }
          if (!allowed) return err("Anh khong thuoc pham vi cua ban", 403);
        }
        if (!env.ANH) return err("Chua cau hinh R2 Object Storage", 501);
        const obj = await env.ANH.get(rec.anh_key);
        if (!obj) return err("Khong tim thay anh", 404);
        const headers = new Headers();
        obj.writeHttpMetadata(headers);
        headers.set("Cache-Control", "private, max-age=3600");
        // Bat buoc phai co header nay thi trinh duyet moi cho trang web (GitHub
        // Pages, Vercel, ...) doc duoc anh tra ve tu Worker — thieu no, fetch
        // se bi chan va bao "Failed to fetch" du Worker van tra anh binh thuong.
        headers.set("Access-Control-Allow-Origin", "*");
        return new Response(obj.body, { headers });
      }
      // ---- Bao cao cham soc diem ban (trong muc Bao cao thong ke) ----
      // Chi admin/subadmin/lanh dao don vi duoc xem (diem ban thuong khong duoc,
      // ke ca khi modules NULL) — pham vi: lanh dao chi thay cay don vi cua minh.
      if (path === "/api/care/reports/summary" && method === "GET") {
        if (!isPrivileged && !isLeader) return err("Chi admin/subadmin va Lanh dao don vi moi xem duoc bao cao cham soc", 403);
        if (!hasModule(me, "reports")) return err("Tai khoan khong co quyen xem bao cao", 403);
        await ensureCareTables(env);
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        if (isLeader && !me.don_vi_id) return json({ ok: true, tong_luot: 0, tong_diem: 0, theo_dot: [], theo_nguoi: [], theo_don_vi: [], theo_diem: [] });
        const prefix = isLeader ? unitSubtreeCTE() + " " : "";
        const scopeSql = isLeader ? " AND p.don_vi_id IN (SELECT id FROM subtree)" : "";
        const runQ = async (sql, extraBinds) => {
          const binds = isLeader ? [me.don_vi_id, ...extraBinds] : extraBinds;
          return (await env.DB.prepare(prefix + sql).bind(...binds).all()).results || [];
        };
        const base = "FROM cham_soc c JOIN nguoi_dung p ON p.id = c.pos_user_id LEFT JOIN dot_cham_soc dt ON dt.id = c.dot_id LEFT JOIN don_vi dv ON dv.id = p.don_vi_id WHERE substr(c.thoi_gian, 1, 10) BETWEEN ? AND ?" + scopeSql;
        const tot = await runQ("SELECT COUNT(*) AS luot, COUNT(DISTINCT c.pos_user_id) AS diem " + base, [from, to]);
        const theoDot = await runQ("SELECT dt.ten_dot AS ten, COUNT(*) AS luot, COUNT(DISTINCT c.pos_user_id) AS diem " + base + " GROUP BY c.dot_id ORDER BY luot DESC", [from, to]);
        const theoNguoi = await runQ("SELECT c.caregiver_ten AS ten, COUNT(*) AS luot, COUNT(DISTINCT c.pos_user_id) AS diem " + base + " GROUP BY c.caregiver_id ORDER BY luot DESC", [from, to]);
        const theoDonVi = await runQ("SELECT COALESCE(dv.ten_don_vi, 'Chưa thuộc đơn vị') AS ten, COUNT(*) AS luot, COUNT(DISTINCT c.pos_user_id) AS diem " + base + " GROUP BY p.don_vi_id ORDER BY luot DESC", [from, to]);
        const theoDiem = await runQ("SELECT p.ho_ten AS ten, COUNT(*) AS luot, MAX(c.thoi_gian) AS lan_cuoi " + base + " GROUP BY c.pos_user_id ORDER BY luot DESC LIMIT 200", [from, to]);
        return json({ ok: true, tong_luot: tot[0] ? tot[0].luot : 0, tong_diem: tot[0] ? tot[0].diem : 0, theo_dot: theoDot, theo_nguoi: theoNguoi, theo_don_vi: theoDonVi, theo_diem: theoDiem });
      }
      if (path === "/api/care/reports/detail" && method === "GET") {
        if (!isPrivileged && !isLeader) return err("Chi admin/subadmin va Lanh dao don vi moi xem duoc bao cao cham soc", 403);
        if (!hasModule(me, "reports")) return err("Tai khoan khong co quyen xem bao cao", 403);
        await ensureCareTables(env);
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        const limit = Math.min(1000, Number(url.searchParams.get("limit")) || 1000);
        if (isLeader && !me.don_vi_id) return json({ ok: true, records: [] });
        const base = "SELECT c.id, c.thoi_gian, dt.ten_dot, p.ho_ten AS pos_ten, d.ten_don_vi AS don_vi_ten, c.caregiver_ten, c.khoang_cach_m, c.ghi_chu FROM cham_soc c JOIN nguoi_dung p ON p.id = c.pos_user_id LEFT JOIN don_vi d ON d.id = p.don_vi_id LEFT JOIN dot_cham_soc dt ON dt.id = c.dot_id WHERE substr(c.thoi_gian, 1, 10) BETWEEN ? AND ?";
        let sql = base;
        let binds = [from, to];
        if (isLeader) {
          sql = unitSubtreeCTE() + " " + base + " AND p.don_vi_id IN (SELECT id FROM subtree)";
          binds = [me.don_vi_id, from, to];
        }
        sql += " ORDER BY c.thoi_gian DESC LIMIT ?";
        binds.push(limit);
        const res = await env.DB.prepare(sql).bind(...binds).all();
        return json({ ok: true, records: res.results || [] });
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

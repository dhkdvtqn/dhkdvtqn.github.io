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
    "SELECT id, ma_kenh, ho_ten, username, role, so_eload, so_vi, ma_hrm, ten_nhan_vien, sdt_nhan_vien, chuc_danh, don_vi_id, loai_kenh, can_import, modules, lat, lng, active FROM nguoi_dung WHERE id = ?"
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
    ma_hrm: u.ma_hrm || "",
    ma_nhan_vien: u.ma_nhan_vien || "",
    chuc_danh: u.chuc_danh || "",
    don_vi_id: u.don_vi_id ?? null,
    don_vi_ten: u.don_vi_ten || "",
    leader_id: u.leader_id ?? null,
    leader_ten: u.leader_ten || "",
    loai_kenh: u.loai_kenh || "",
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
    if (!cols.has("leader_id")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN leader_id INTEGER").run();
    if (!cols.has("loai_kenh")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN loai_kenh TEXT").run();
    if (!cols.has("ma_nhan_vien")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN ma_nhan_vien TEXT").run();
    if (!cols.has("chuc_danh")) await env.DB.prepare("ALTER TABLE nguoi_dung ADD COLUMN chuc_danh TEXT").run();
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
const MODULE_KEYS = ["dashboard", "salesdash", "units", "users", "import", "config", "reports", "packages", "loginstats", "settings", "care", "channelmap", "staff"];

// Chuan hoa loai kenh ban: nhan ma (DUQ/DBL/GARA/DDV) hoac ten day du
// (khong phan biet hoa/thuong, khong dau). Chuan hoa ve dang khong dau
// truoc khi so sanh de "đbl"/"điểm ủy quyền bán đa dịch vụ" deu nhan ra.
// Kiem tra DDV truoc DUQ vi ten day du cua DDV co chua cum "uy quyen".
// Tra ve "" neu khong nhan ra.
function normLoaiKenh(v) {
  const s = String(v || "").trim().toUpperCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/Đ/g, "D");
  if (["DUQ", "DBL", "GARA", "DDV"].includes(s)) return s;
  if (s.includes("DDV") || s.includes("DA DICH VU")) return "DDV";
  if (s.includes("DBL") || s.includes("BAN LE")) return "DBL";
  if (s.includes("GARA")) return "GARA";
  if (s.includes("DUQ") || s.includes("UY QUYEN")) return "DUQ";
  return "";
}
const DEFAULT_MODULES = ["dashboard", "reports", "packages", "settings"];
// Lanh dao don vi mac dinh them module Cham soc diem ban
const LEADER_MODULES = [...DEFAULT_MODULES, "care"];
// Danh sach chuc danh trong module Quan ly nguoi dung (nhan su noi bo)
const CHUC_DANH_LIST = ["Lãnh đạo đơn vị", "Chuyên viên", "Nhân viên kinh doanh", "Quản trị viên"];
// Chuc danh + co SubAdmin -> role he thong
function staffRoleFrom(chucDanh, isSubAdmin) {
  if (isSubAdmin) return "subadmin";
  const cd = String(chucDanh || "").trim();
  if (cd === "Quản trị viên") return "admin";
  if (cd === "Lãnh đạo đơn vị") return "leader";
  return "staff"; // Chuyên viên / Nhân viên kinh doanh: chi xem so lieu cua chinh minh
}
// Module mac dinh khi tao tai khoan nhan su (admin khong tich tay)
function defaultModulesForRole(role) {
  if (role === "admin") return null;
  if (role === "leader") return JSON.stringify(LEADER_MODULES);
  return JSON.stringify(DEFAULT_MODULES);
}
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
    key_col: "", kenh_col: "",
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
    // Cot khoa nghiep vu: chi dung lam can cu map bao cao (doi chieu voi
    // ma_hrm / sdt_nhan_vien cua user), KHONG lam PRIMARY KEY — bang thang
    // van dung id tu tang de import du het cac dong ke ca khi khoa trung nhau.
    key_col: "ma_hrm_sdt_smcs",
    // Cot Ma kenh: map bao cao theo ma_kenh cua user (dinh danh diem ban on
    // dinh nhat, co san ca o tai khoan cu chua co so_vi/ma_hrm).
    kenh_col: "ma_kenh",
  },
];

// Dinh dang cu cua cac loai du lieu, de bao cao van doc duoc bang thang cu sau
// khi dinh nghia loai doi sang mau moi (VD: BCKH doi sang 18 truong moi thang
// 10/2026, cac bang BCKH thang cu van theo 9 truong cu). Khi truy van 1 bang
// theo dinh nghia moi that bai (thieu cot), bao cao thu lai theo dinh dang cu;
// chi bo qua bang khi ca hai dinh dang deu khong doc duoc. Khong sua du lieu.
const LEGACY_SCHEMAS = {
  BCKH: {
    money_col: "hoa_hong_bckh", time_col: "thoi_gian_chi_tra", time_fallback_col: "",
    eload_col: "so_eload", vi_col: "", sub_col: "so_thue_bao", pkg_col: "",
    trans_col: "ma_giao_dich", status_col: "trang_thai", reason_col: "nguyen_nhan_loi", key_col: "", kenh_col: "",
  },
};
async function ensureTypes(env) {
  await env.DB.prepare(
    "CREATE TABLE IF NOT EXISTS loai_du_lieu (" +
    "id INTEGER PRIMARY KEY AUTOINCREMENT, code TEXT UNIQUE NOT NULL, name TEXT NOT NULL, " +
    "prefix TEXT NOT NULL, fmt TEXT NOT NULL DEFAULT 'MMYYYY', columns_json TEXT NOT NULL, " +
    "money_col TEXT, time_col TEXT, time_fallback_col TEXT, eload_col TEXT, vi_col TEXT, " +
    "sub_col TEXT, pkg_col TEXT, trans_col TEXT, status_col TEXT, reason_col TEXT, key_col TEXT, kenh_col TEXT, " +
    "sales_unit_col TEXT, sales_eload_col TEXT, sales_kenh_col TEXT, sales_price_col TEXT, sales_qty_col TEXT, " +
    "sales_result_col TEXT, sales_subtype_col TEXT, sales_kind TEXT, " +
    "builtin INTEGER NOT NULL DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)"
  ).run();
  // CSDL cu co the chua co cot key_col / kenh_col (them sau) — bo sung neu thieu.
  try {
    const info = await env.DB.prepare("PRAGMA table_info(loai_du_lieu)").all();
    const names = new Set((info.results || []).map((c) => c.name));
    if (!names.has("key_col")) await env.DB.prepare("ALTER TABLE loai_du_lieu ADD COLUMN key_col TEXT").run();
    if (!names.has("kenh_col")) await env.DB.prepare("ALTER TABLE loai_du_lieu ADD COLUMN kenh_col TEXT").run();
    for (const c of ["sales_unit_col", "sales_eload_col", "sales_kenh_col", "sales_price_col", "sales_qty_col", "sales_result_col", "sales_subtype_col", "sales_kind"]) {
      if (!names.has(c)) await env.DB.prepare("ALTER TABLE loai_du_lieu ADD COLUMN " + c + " TEXT").run();
    }
  } catch (e) { /* PRAGMA khong co thi bo qua, cot se duoc them o lan tao bang sau */ }
  const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM loai_du_lieu").first();
  if (c && c.n === 0) {
    for (const t of BUILTIN_TYPES) {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO loai_du_lieu (code, name, prefix, fmt, columns_json, money_col, time_col, time_fallback_col, eload_col, vi_col, sub_col, pkg_col, trans_col, status_col, reason_col, key_col, kenh_col, builtin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)"
      )
        .bind(t.code, t.name, t.prefix, t.fmt, JSON.stringify(t.columns), t.money_col, t.time_col, t.time_fallback_col, t.eload_col, t.vi_col, t.sub_col, t.pkg_col, t.trans_col, t.status_col, t.reason_col, t.key_col || "", t.kenh_col || "")
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
        "INSERT OR IGNORE INTO loai_du_lieu (code, name, prefix, fmt, columns_json, money_col, time_col, time_fallback_col, eload_col, vi_col, sub_col, pkg_col, trans_col, status_col, reason_col, key_col, kenh_col, builtin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)"
      )
        .bind(t.code, t.name, t.prefix, t.fmt, JSON.stringify(t.columns), t.money_col, t.time_col, t.time_fallback_col, t.eload_col, t.vi_col, t.sub_col, t.pkg_col, t.trans_col, t.status_col, t.reason_col, t.key_col || "", t.kenh_col || "")
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
        (cur.reason_col || "") === (t.reason_col || "") && (cur.key_col || "") === (t.key_col || "") &&
        (cur.kenh_col || "") === (t.kenh_col || "");
      if (!same) {
        await env.DB.prepare(
          "UPDATE loai_du_lieu SET name = ?, prefix = ?, fmt = ?, columns_json = ?, money_col = ?, time_col = ?, time_fallback_col = ?, eload_col = ?, vi_col = ?, sub_col = ?, pkg_col = ?, trans_col = ?, status_col = ?, reason_col = ?, key_col = ?, kenh_col = ? WHERE code = ?"
        )
          .bind(t.name, t.prefix, t.fmt, JSON.stringify(t.columns), t.money_col, t.time_col, t.time_fallback_col, t.eload_col, t.vi_col, t.sub_col, t.pkg_col, t.trans_col, t.status_col, t.reason_col, t.key_col || "", t.kenh_col || "", t.code)
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
function buildSource(t, meUser, overrideUnitId) {
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
  // Cot Ma kenh: dinh danh diem ban on dinh nhat (co san ca o tai khoan cu).
  if (t.kenh_col) { ownParts.push(t.kenh_col + " = ?"); ownBinds.push(meUser.ma_kenh || "__none__"); }
  // Loc theo don vi (danh cho Lanh dao don vi): cac giao dich cua user
  // thuoc don vi cua lanh dao VA MOI DON VI TRUC THUOC trong cay don vi
  // (don_vi.parent_id) — vi du lanh dao cap tinh thay toan tinh, lanh dao
  // cap khu vuc chi thay khu vuc do + cac don vi con cua no. Map qua
  // so_eload / so_vi trong bang nguoi_dung.
  // overrideUnitId: khi loc bao cao theo 1 don vi cu the (tham so don_vi),
  // cay lay goc tai don vi do thay vi don vi cua nguoi dung.
  const unitRoot = overrideUnitId != null ? overrideUnitId : meUser.don_vi_id;
  const unitParts = [], unitBinds = [];
  if (unitRoot) {
    const subtree = "WITH RECURSIVE subtree(id) AS (SELECT ? UNION ALL SELECT d.id FROM don_vi d JOIN subtree s ON d.parent_id = s.id)";
    if (t.eload_col) { unitParts.push(t.eload_col + " IN (" + subtree + " SELECT so_eload FROM nguoi_dung WHERE don_vi_id IN (SELECT id FROM subtree))"); unitBinds.push(unitRoot); }
    if (t.vi_col) { unitParts.push(t.vi_col + " IN (" + subtree + " SELECT so_vi FROM nguoi_dung WHERE don_vi_id IN (SELECT id FROM subtree))"); unitBinds.push(unitRoot); }
    if (t.key_col) {
      unitParts.push(t.key_col + " IN (" + subtree + " SELECT ma_hrm FROM nguoi_dung WHERE don_vi_id IN (SELECT id FROM subtree))"); unitBinds.push(unitRoot);
      unitParts.push(t.key_col + " IN (" + subtree + " SELECT sdt_nhan_vien FROM nguoi_dung WHERE don_vi_id IN (SELECT id FROM subtree))"); unitBinds.push(unitRoot);
    }
    if (t.kenh_col) { unitParts.push(t.kenh_col + " IN (" + subtree + " SELECT ma_kenh FROM nguoi_dung WHERE don_vi_id IN (SELECT id FROM subtree))"); unitBinds.push(unitRoot); }
  }
  // Loc "Chua xac dinh" (don_vi ao, chi admin/subadmin): cac dong KHONG map
  // duoc voi bat ky user nao co don vi (user chua gan don vi hoac dong khong
  // khop dinh danh nao). Moi chieu map deu chan NULL/rong de tranh kieu
  // 3 gia tri cua SQL lam mat dong (vd: dong chi co ma_kenh khong khop van
  // phai roi vao "Chua xac dinh" du so_vi cua no la NULL).
  const unmappedParts = [];
  if (t.eload_col) unmappedParts.push("(" + t.eload_col + " IS NOT NULL AND " + t.eload_col + " <> '' AND " + t.eload_col + " IN (SELECT so_eload FROM nguoi_dung WHERE don_vi_id IS NOT NULL AND so_eload IS NOT NULL AND so_eload <> ''))");
  if (t.vi_col) unmappedParts.push("(" + t.vi_col + " IS NOT NULL AND " + t.vi_col + " <> '' AND " + t.vi_col + " IN (SELECT so_vi FROM nguoi_dung WHERE don_vi_id IS NOT NULL AND so_vi IS NOT NULL AND so_vi <> ''))");
  if (t.key_col) unmappedParts.push("((" + t.key_col + " IS NOT NULL AND " + t.key_col + " <> '' AND " + t.key_col + " IN (SELECT ma_hrm FROM nguoi_dung WHERE don_vi_id IS NOT NULL AND ma_hrm IS NOT NULL AND ma_hrm <> '')) OR (" + t.key_col + " IS NOT NULL AND " + t.key_col + " <> '' AND " + t.key_col + " IN (SELECT sdt_nhan_vien FROM nguoi_dung WHERE don_vi_id IS NOT NULL AND sdt_nhan_vien IS NOT NULL AND sdt_nhan_vien <> '')))");
  if (t.kenh_col) unmappedParts.push("(" + t.kenh_col + " IS NOT NULL AND " + t.kenh_col + " <> '' AND " + t.kenh_col + " IN (SELECT ma_kenh FROM nguoi_dung WHERE don_vi_id IS NOT NULL AND ma_kenh IS NOT NULL AND ma_kenh <> ''))");
  const unmapped = unmappedParts.length ? "NOT (" + unmappedParts.join(" OR ") + ")" : "1=1";
  return {
    code: t.code, prefix: t.prefix, money: t.money_col, time,
    type: t,
    own: ownParts.length ? "(" + ownParts.join(" OR ") + ")" : "(1 = 0)",
    ownBinds,
    unit: unitParts.length ? "(" + unitParts.join(" OR ") + ")" : "(1 = 0)",
    unitBinds,
    eloadCol: t.eload_col || null, viCol: t.vi_col || null,
    subCol: t.sub_col || null, pkgCol: t.pkg_col || null,
    transCol: t.trans_col || null, statusCol: t.status_col || null, reasonCol: t.reason_col || null,
    keyCol: t.key_col || null, kenhCol: t.kenh_col || null,
    unmapped,
  };
}

// Giai quyet tham so loc don_vi cho bao cao: admin/subadmin duoc loc bat ky
// don vi; lanh dao chi duoc loc don vi trong cay cua minh; user thuong khong
// duoc loc. Tra ve { ok, unit } — unit null nghia la khong loc.
async function resolveScopeUnit(env, me, isLeaderLike, isPrivileged, donViParam) {
  if (donViParam === null || donViParam === undefined || donViParam === "") return { ok: true, unit: null };
  // Don vi ao "Chua xac dinh" (don_vi=0): so lieu chua map duoc voi don vi
  // nao — chi admin/subadmin moi xem duoc vi so lieu nay nam ngoai moi cay
  // don vi cua lanh dao.
  if (donViParam === "0" || donViParam === 0) {
    if (!isPrivileged) return { ok: false, msg: "So lieu chua xac dinh don vi chi admin/subadmin moi xem duoc", code: 403 };
    return { ok: true, unit: 0 };
  }
  const id = Number(donViParam);
  if (!id) return { ok: false, msg: "Don vi loc khong hop le", code: 422 };
  const unit = await env.DB.prepare("SELECT id FROM don_vi WHERE id = ?").bind(id).first();
  if (!unit) return { ok: false, msg: "Don vi khong ton tai: " + donViParam, code: 422 };
  if (!isPrivileged) {
    if (!isLeaderLike || !me.don_vi_id) return { ok: false, msg: "Tai khoan khong co quyen loc theo don vi", code: 403 };
    const inside = await env.DB.prepare(unitSubtreeCTE() + " SELECT 1 FROM don_vi WHERE id = ? AND id IN (SELECT id FROM subtree)").bind(me.don_vi_id, id).first();
    if (!inside) return { ok: false, msg: "Don vi khong thuoc pham vi cua ban", code: 403 };
  }
  return { ok: true, unit: id };
}

// Giai ma tham so loc "Theo diem ban" (?diem_ban=<id>): chi nhan tai khoan
// diem ban (role='user'). Admin/subadmin loc diem ban bat ky; lanh dao
// (va chuyen vien tuong duong) chi loc diem ban trong cay don vi cua minh;
// user thuong/nhan su khac chi duoc loc chinh minh.
async function resolvePosUser(env, me, isPrivileged, isLeaderLike, posParam) {
  if (posParam === null || posParam === undefined || posParam === "") return { ok: true, pos: null };
  const id = Number(posParam);
  if (!id) return { ok: false, msg: "Diem ban loc khong hop le", code: 422 };
  const pos = await env.DB.prepare(
    "SELECT id, ho_ten, username, role, so_eload, so_vi, ma_hrm, sdt_nhan_vien, ma_kenh, don_vi_id FROM nguoi_dung WHERE id = ?"
  ).bind(id).first();
  if (!pos || pos.role !== "user") return { ok: false, msg: "Diem ban khong ton tai", code: 422 };
  if (!isPrivileged) {
    if (isLeaderLike && me.don_vi_id) {
      if (!pos.don_vi_id) return { ok: false, msg: "Diem ban khong thuoc pham vi cua ban", code: 403 };
      const inside = await env.DB.prepare(unitSubtreeCTE() + " SELECT 1 FROM don_vi WHERE id = ? AND id IN (SELECT id FROM subtree)").bind(me.don_vi_id, pos.don_vi_id).first();
      if (!inside) return { ok: false, msg: "Diem ban khong thuoc pham vi cua ban", code: 403 };
    } else if (pos.id !== me.id) {
      return { ok: false, msg: "Ban chi duoc loc theo diem ban cua chinh minh", code: 403 };
    }
  }
  return { ok: true, pos };
}

// Chuan hoa trang thai chi tra de xep vao nhom "Thanh cong" / "Khong thanh cong".
// Thanh cong = dung 1 trong 2 trang thai anh Tuan chot: "Thanh cong" hoac
// "Da chi tra thu lao thanh cong" (khong phan biet hoa/thuong, co/khong dau,
// thua khoang trang). Moi trang thai khac (ke ca de trong) = khong thanh cong.
function normStatus(s) {
  return String(s || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/đ/g, "d").replace(/Đ/g, "D").toLowerCase().trim();
}
function isSuccessStatus(s) {
  const n = normStatus(s);
  return n === "thanh cong" || n === "da chi tra thu lao thanh cong";
}
// Tham so loc trang thai chi tra (?trang_thai=): "success" (mac dinh) = chi
// tinh giao dich thanh cong; "fail" = chi tinh giao dich khong thanh cong;
// "all" = tinh tat ca (khong loc theo trang thai).
function parseStatusFilter(v) { return v === "fail" ? "fail" : v === "all" ? "all" : "success"; }

// Tong hop bao cao dung chung cho /api/reports/summary va /api/reports/by-unit.
// scopeUnit: null = pham vi mac dinh theo vai tro; so = goc cay don vi can loc.
// statusFilter: "success" (mac dinh) / "fail" / "all" (khong loc).
async function aggregateSummary(env, me, isPrivileged, isUnitScoped, { from, to, group, loai, scopeUnit, statusFilter, posUser }) {
  const groupExpr = group === "month" ? "substr(tg, 1, 7)" : "substr(tg, 1, 10)";
  const stFilter = parseStatusFilter(statusFilter);
  const types = await getDataTypes(env);
  const sources = types
    .filter((t) => (loai === "ALL" || t.code === loai) && t.money_col && t.time_col)
    .map((t) => buildSource(t, posUser || me, scopeUnit));
  // Truy van tung bang thang roi cong don ket qua trong JS.
  // (Cach cu ghep tat ca bang bang UNION ALL thanh 1 cau SQL khong lo
  //  se vuot gioi han "too many terms in compound SELECT" cua D1.)
  const agg = new Map();
  // Bang thang cu khong khop dinh nghia moi thi thu doc theo dinh dang cu
  // (VD: bang BCKH thang cu theo mau cu) — chi bo qua co bao cao khi ca
  // hai dinh dang deu khong doc duoc, thay vi lam hong toan bo bao cao.
  const skippedTables = [];
  const legacyTables = [];
  for (const s of sources) {
    const tables = await listMonthlyTables(env, s.prefix);
    for (const t of tables) {
      if (!tableInRange(t, s.prefix, from, to)) continue;
      const runSummaryTable = async (src) => {
        const buildSQL = (withStatus) => {
          const innerCols = [src.time + " AS tg", src.money + " AS tien"];
          if (src.eloadCol) innerCols.push(src.eloadCol);
          if (src.viCol) innerCols.push(src.viCol);
          if (src.keyCol) innerCols.push(src.keyCol);
          if (src.kenhCol) innerCols.push(src.kenhCol);
          if (withStatus) innerCols.push('"' + src.statusCol + '" AS tt');
          let sql =
            'SELECT ' + groupExpr + ' AS ky' + (withStatus ? ', tt' : '') + ', COUNT(*) AS so_giao_dich, COALESCE(SUM(tien), 0) AS tong_tien FROM (SELECT ' +
            innerCols.join(", ") + ' FROM "' + t + '") WHERE substr(tg, 1, 10) BETWEEN ? AND ?';
          const localBinds = [from, to];
          if (posUser) { sql += " AND " + src.own; localBinds.push(...src.ownBinds); }
          else if (scopeUnit != null) {
            if (scopeUnit === 0) { sql += " AND " + src.unmapped; }
            else { sql += " AND " + src.unit; localBinds.push(...src.unitBinds); }
          }
          else if (!isPrivileged) {
            if (isUnitScoped) { sql += " AND " + src.unit; localBinds.push(...src.unitBinds); }
            else { sql += " AND " + src.own; localBinds.push(...src.ownBinds); }
          }
          sql += withStatus ? " GROUP BY ky, tt" : " GROUP BY ky";
          return { sql, localBinds };
        };
        // Uu tien doc kem cot trang thai de phan nhom success/fail trong JS
        // (chuan hoa day du: hoa/thuong, dau, khoang trang — tranh bay "Khong
        // thanh cong" neu so sanh chuoi don gian). Bang khong co cot trang
        // thai thi roi ve cach tinh cu: success cong het, fail bo qua.
        if (src.statusCol) {
          try {
            const q = buildSQL(true);
            const r = await env.DB.prepare(q.sql).bind(...q.localBinds).all();
            return { rows: r.results || [], withStatus: true };
          } catch (e) {
            if (!/no such column/i.test(e.message || "")) throw e;
          }
        }
        const q = buildSQL(false);
        const r = await env.DB.prepare(q.sql).bind(...q.localBinds).all();
        return { rows: r.results || [], withStatus: false };
      };
      let res, usedLegacy = false;
      try { res = await runSummaryTable(s); }
      catch (e) {
        const legacy = LEGACY_SCHEMAS[s.code];
        if (!legacy || !s.type) { skippedTables.push(t); continue; }
        try { res = await runSummaryTable(buildSource({ ...s.type, ...legacy }, posUser || me, scopeUnit)); usedLegacy = true; }
        catch (e2) { skippedTables.push(t); continue; }
      }
      if (usedLegacy) legacyTables.push(t);
      for (const r of res.rows || []) {
        if (stFilter !== "all") {
          if (res.withStatus) {
            if ((isSuccessStatus(r.tt) ? "success" : "fail") !== stFilter) continue;
          } else if (stFilter === "fail") continue;
        }
        const cur = agg.get(r.ky) || { ky: r.ky, so_giao_dich: 0, tong_tien: 0 };
        cur.so_giao_dich += r.so_giao_dich || 0;
        cur.tong_tien += r.tong_tien || 0;
        agg.set(r.ky, cur);
      }
    }
  }
  const rows = [...agg.values()].sort((a, b) => String(a.ky || "").localeCompare(String(b.ky || "")));
  return {
    rows,
    tong_giao_dich: rows.reduce((a, r) => a + (r.so_giao_dich || 0), 0),
    tong_tien: rows.reduce((a, r) => a + (r.tong_tien || 0), 0),
    skipped_tables: skippedTables,
    legacy_tables: legacyTables,
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
      // Chuyen vien (nhan su noi bo role staff + chuc danh "Chuyên viên"):
      // duoc xem so lieu tuong duong Lanh dao don vi — pham vi cay don vi
      // cua minh. Khong ap dung cho module Cham soc diem ban (van chi
      // admin/lanh dao duoc gan diem truc tiep).
      const isLeaderLike = isLeader || (me.role === "staff" && me.chuc_danh === "Chuyên viên");
      // Lanh dao don vi: xem du lieu cua cac user trong don vi cua minh VA
      // cac don vi truc thuoc (cay don_vi qua parent_id); neu chua gan don
      // vi thi tam xem du lieu cua chinh minh.
      const isUnitScoped = isLeaderLike && !!me.don_vi_id;
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

      // ---- Quan ly kenh ban (module "Quan ly kenh ban", key users) va
      // Quan ly nguoi dung noi bo (module "Quan ly nguoi dung", key staff).
      // kind=channel: chi tai khoan diem ban (role='user');
      // kind=staff: tai khoan noi bo (admin/subadmin/leader/staff).
      if (path === "/api/users" && method === "GET") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen xem danh sach", 403);
        const kind = url.searchParams.get("kind");
        const needKey = kind === "staff" ? "staff" : kind === "channel" ? "users" : null;
        if (needKey ? !hasModule(me, needKey) : !(hasModule(me, "users") || hasModule(me, "staff")))
          return err("Tai khoan khong co quyen su dung module nay", 403);
        const where = kind === "channel" ? " WHERE u.role = 'user'" : kind === "staff" ? " WHERE u.role != 'user'" : "";
        const res = await env.DB.prepare(
          "SELECT u.id, u.ma_kenh, u.ho_ten, u.username, u.role, u.so_eload, u.so_vi, u.ten_nhan_vien, u.sdt_nhan_vien, u.ma_hrm, u.ma_nhan_vien, u.chuc_danh, u.don_vi_id, d.ten_don_vi AS don_vi_ten, u.leader_id, l.ho_ten AS leader_ten, u.loai_kenh, u.can_import, u.modules, u.lat, u.lng, u.active FROM nguoi_dung u LEFT JOIN don_vi d ON d.id = u.don_vi_id LEFT JOIN nguoi_dung l ON l.id = u.leader_id" + where + " ORDER BY u.ho_ten"
        ).all();
        return json({ ok: true, users: (res.results || []).map(publicUser) });
      }
      // Danh sach chuc danh trong module Quan ly nguoi dung (nhan su noi bo)
      const CHUC_DANH_LIST = ["Lãnh đạo đơn vị", "Chuyên viên", "Nhân viên kinh doanh", "Quản trị viên"];
      // Chuc danh + co SubAdmin -> role he thong
      const staffRoleFrom = (chucDanh, isSubAdmin) => {
        if (isSubAdmin) return "subadmin";
        const cd = String(chucDanh || "").trim();
        if (cd === "Quản trị viên") return "admin";
        if (cd === "Lãnh đạo đơn vị") return "leader";
        return "staff"; // Chuyên viên / Nhân viên kinh doanh: chi xem so lieu cua chinh minh
      };
      // Module mac dinh khi tao tai khoan nhan su (admin khong tich tay)
      const defaultModulesForRole = (role) => {
        if (role === "admin") return null;
        if (role === "leader") return JSON.stringify(LEADER_MODULES);
        return JSON.stringify(DEFAULT_MODULES);
      };
      if (path === "/api/users" && method === "POST") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen tao nguoi dung", 403);
        const b = await readBody(request);
        const kind = b.kind === "staff" ? "staff" : "channel";
        const needKey = kind === "staff" ? "staff" : "users";
        if (!hasModule(me, needKey)) return err("Tai khoan khong co quyen su dung module nay", 403);
        if (!toText(b.ho_ten) || !toText(b.username)) return err("Thieu ho ten hoac user dang nhap", 422);
        const salt = randomSalt();
        const password = String(b.password || "Vnpt@2026");
        const hash = await hashPassword(password, salt);
        let newRole, newCanImport, newModules, newMaNv = "", newChucDanh = "";
        if (kind === "channel") {
          // Kenh ban: luon la user, khong co quyen import; mac dinh 4 module
          // (Dashboard, Bao cao thong ke, Danh muc goi cuoc, Cai dat).
          newRole = "user";
          newCanImport = 0;
          if (isAdmin && Array.isArray(b.modules)) newModules = JSON.stringify(b.modules.filter((k) => MODULE_KEYS.includes(k)));
          else newModules = JSON.stringify(DEFAULT_MODULES);
        } else {
          newMaNv = toText(b.ma_nhan_vien);
          newChucDanh = toText(b.chuc_danh);
          if (newChucDanh && !CHUC_DANH_LIST.includes(newChucDanh)) return err("Chuc danh khong hop le", 422);
          if (isAdmin) {
            newRole = staffRoleFrom(newChucDanh, b.subadmin);
            newCanImport = b.can_import ? 1 : 0;
          } else {
            // SubAdmin tao nhan su: khong duoc cap subadmin/admin
            newRole = newChucDanh === "Lãnh đạo đơn vị" ? "leader" : "staff";
            newCanImport = 0;
          }
          if (isAdmin && Array.isArray(b.modules)) newModules = JSON.stringify(b.modules.filter((k) => MODULE_KEYS.includes(k)));
          else newModules = defaultModulesForRole(newRole);
        }
        const latP = parseCoordField(b.lat, -90, 90);
        if (latP.error) return err("Vi do diem ban khong hop le (tu -90 den 90)", 422);
        const lngP = parseCoordField(b.lng, -180, 180);
        if (lngP.error) return err("Kinh do diem ban khong hop le (tu -180 den 180)", 422);
        // Lanh dao phu trach: chi nhan id cua tai khoan co role leader.
        let newLeaderId = null;
        if (b.leader_id) {
          const ld = await env.DB.prepare("SELECT id FROM nguoi_dung WHERE id = ? AND role = 'leader'").bind(Number(b.leader_id)).first();
          if (!ld) return err("Lanh dao phu trach khong ton tai hoac khong phai tai khoan Lanh dao don vi", 422);
          newLeaderId = ld.id;
        }
        // Loai kenh ban: DUQ/DBL/GARA/DDV (hoac de trong).
        const newLoaiKenh = normLoaiKenh(b.loai_kenh);
        if (toText(b.loai_kenh) && !newLoaiKenh) return err("Loai kenh ban khong hop le (DUQ/DBL/GARA/DDV)", 422);
        const r = await env.DB.prepare(
          "INSERT INTO nguoi_dung (ma_kenh, ho_ten, username, password_hash, salt, role, so_eload, so_vi, ten_nhan_vien, sdt_nhan_vien, ma_hrm, ma_nhan_vien, chuc_danh, don_vi_id, leader_id, loai_kenh, can_import, modules, lat, lng) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
          .bind(
            toText(b.ma_kenh), toText(b.ho_ten), toText(b.username), hash, salt,
            newRole,
            toText(b.so_eload), toText(b.so_vi), toText(b.ten_nhan_vien), toText(b.sdt_nhan_vien), toText(b.ma_hrm),
            newMaNv, newChucDanh,
            b.don_vi_id ? Number(b.don_vi_id) : null, newLeaderId, newLoaiKenh, newCanImport, newModules, latP.val, lngP.val
          )
          .run();
        return json({ ok: true, id: r.meta.last_row_id });
      }
      // ---- Import nguoi dung tu Excel (kind=channel: diem ban; kind=staff: nhan su noi bo) ----
      if (path === "/api/users/import" && method === "POST") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen import", 403);
        const b = await readBody(request);
        const kind = b.kind === "staff" ? "staff" : "channel";
        const needKey = kind === "staff" ? "staff" : "users";
        if (!hasModule(me, needKey)) return err("Tai khoan khong co quyen su dung module nay", 403);
        const rows = Array.isArray(b.rows) ? b.rows : [];
        if (!rows.length) return err("Khong co dong du lieu nao de import", 422);
        // Che do import: create (mac dinh) | update | replace
        // - create: chi them user chua co; user da ton tai thi bo qua.
        // - update: user da co thi cap nhat cac truong co du lieu moi trong file
        //   (truong de trong thi giu nguyen); chua co thi tao moi.
        // - replace: user da co thi ghi de toan bo thong tin theo file
        //   (truong de trong thi xoa); chua co thi tao moi.
        // Import khong bao gio doi role / can_import / modules cua user da co
        // (doi cac quyen nay trong form Sua); mat khau de trong thi giu nguyen
        // mat khau cu (tao moi thi dung mac dinh Vnpt@2026).
        const impMode = b.mode === "update" ? "update" : b.mode === "replace" ? "replace" : "create";
        let created = 0, updated = 0, skipped = 0;
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
          const existing = await env.DB.prepare("SELECT id FROM nguoi_dung WHERE username = ?").bind(username).first();
          // Don vi: nhan id truc tiep, hoac tra theo ma/ten don vi trong file Excel
          let donViId = null, donViOk = false;
          if (r.don_vi_id) { donViId = Number(r.don_vi_id) || null; donViOk = true; }
          else if (toText(r.don_vi)) {
            const dv = await env.DB.prepare("SELECT id FROM don_vi WHERE ma_don_vi = ? OR ten_don_vi = ?")
              .bind(toText(r.don_vi), toText(r.don_vi))
              .first();
            if (dv) { donViId = dv.id; donViOk = true; }
            else warnings.push({ row: i + 2, reason: "Khong tim thay don vi '" + toText(r.don_vi) + "' — da de trong" });
          }
          // Toa do / Lanh dao phu trach / Loai kenh ban: chi ap dung cho diem ban (kind=channel)
          let impLat = null, impLng = null, latOk = false, lngOk = false;
          let leaderId = null, leaderOk = false;
          let impLoaiKenh = "";
          if (kind === "channel") {
            if (toText(r.lat) !== "") {
              const p = parseCoordField(r.lat, -90, 90);
              if (p.error) warnings.push({ row: i + 2, reason: "Vi do khong hop le — da giu nguyen" });
              else { impLat = p.val; latOk = true; }
            }
            if (toText(r.lng) !== "") {
              const p = parseCoordField(r.lng, -180, 180);
              if (p.error) warnings.push({ row: i + 2, reason: "Kinh do khong hop le — da giu nguyen" });
              else { impLng = p.val; lngOk = true; }
            }
            if (toText(r.leader_username)) {
              const ld = await env.DB.prepare("SELECT id FROM nguoi_dung WHERE username = ? AND role = 'leader'").bind(toText(r.leader_username)).first();
              if (ld) { leaderId = ld.id; leaderOk = true; }
              else warnings.push({ row: i + 2, reason: "Khong tim thay tai khoan lanh dao '" + toText(r.leader_username) + "' — da de trong" });
            }
            impLoaiKenh = normLoaiKenh(r.loai_kenh);
            if (toText(r.loai_kenh) && !impLoaiKenh) warnings.push({ row: i + 2, reason: "Loai kenh ban '" + toText(r.loai_kenh) + "' khong nhan ra — da de trong" });
          }
          // Truong nhan su: chi ap dung cho kind=staff
          let impMaNv = "", impChucDanh = "Nhân viên kinh doanh", impSubAdmin = false, impCanImport = 0, impModules = null;
          if (kind === "staff") {
            impMaNv = toText(r.ma_nhan_vien);
            const cdRaw = toText(r.chuc_danh);
            if (cdRaw && !CHUC_DANH_LIST.includes(cdRaw)) warnings.push({ row: i + 2, reason: "Chuc danh '" + cdRaw + "' khong hop le — da dung 'Nhân viên kinh doanh'" });
            else if (cdRaw) impChucDanh = cdRaw;
            impSubAdmin = !!r.subadmin;
            impCanImport = isAdmin && r.can_import ? 1 : 0;
            if (isAdmin && toText(r.modules)) {
              const keys = String(r.modules).split(",").map((s) => s.trim().toLowerCase()).filter((k) => MODULE_KEYS.includes(k));
              if (keys.length) impModules = JSON.stringify(keys);
              else warnings.push({ row: i + 2, reason: "Cot Modules khong co ma hop le — da dung mac dinh theo chuc danh" });
            }
          }
          if (existing) {
            if (impMode === "create") {
              skipped++;
              errors.push({ row: i + 2, reason: "User dang nhap da ton tai: " + username });
              continue;
            }
            const sets = [], binds = [];
            const setText = (col, raw) => {
              const v = toText(raw);
              if (impMode === "update") { if (v) { sets.push(col + " = ?"); binds.push(v); } }
              else { sets.push(col + " = ?"); binds.push(v); }
            };
            if (kind === "staff") {
              // Nhan su: chi cap nhat thong tin hanh chinh; khong doi role/can_import/modules
              setText("ma_nhan_vien", r.ma_nhan_vien);
              setText("ho_ten", r.ho_ten);
              if (impMode === "replace") { sets.push("chuc_danh = ?"); binds.push(impChucDanh); }
              else if (toText(r.chuc_danh)) { sets.push("chuc_danh = ?"); binds.push(impChucDanh); }
              if (impMode === "replace") { sets.push("don_vi_id = ?"); binds.push(donViOk ? donViId : null); }
              else if (donViOk) { sets.push("don_vi_id = ?"); binds.push(donViId); }
            } else {
              setText("ma_kenh", r.ma_kenh);
              setText("ho_ten", r.ho_ten);
              setText("so_eload", r.so_eload);
              setText("so_vi", r.so_vi);
              setText("ten_nhan_vien", r.ten_nhan_vien);
              setText("sdt_nhan_vien", r.sdt_nhan_vien);
              setText("ma_hrm", r.ma_hrm);
              if (impMode === "replace") { sets.push("loai_kenh = ?"); binds.push(impLoaiKenh); }
              else if (impLoaiKenh) { sets.push("loai_kenh = ?"); binds.push(impLoaiKenh); }
              if (impMode === "replace") { sets.push("don_vi_id = ?"); binds.push(donViOk ? donViId : null); }
              else if (donViOk) { sets.push("don_vi_id = ?"); binds.push(donViId); }
              if (impMode === "replace") { sets.push("leader_id = ?"); binds.push(leaderOk ? leaderId : null); }
              else if (leaderOk) { sets.push("leader_id = ?"); binds.push(leaderId); }
              if (impMode === "replace") { sets.push("lat = ?"); binds.push(latOk ? impLat : null); sets.push("lng = ?"); binds.push(lngOk ? impLng : null); }
              else { if (latOk) { sets.push("lat = ?"); binds.push(impLat); } if (lngOk) { sets.push("lng = ?"); binds.push(impLng); } }
            }
            const pw = String(r.password || "");
            let pwHash = null, pwSalt = null;
            if (pw) { pwSalt = randomSalt(); pwHash = await hashPassword(pw, pwSalt); }
            if (sets.length || pwHash) {
              let sql = "UPDATE nguoi_dung SET " + sets.join(", ");
              if (pwHash) sql += (sets.length ? ", " : "") + "password_hash = ?, salt = ?";
              sql += " WHERE id = ?";
              const allBinds = binds.concat(pwHash ? [pwHash, pwSalt] : []).concat([existing.id]);
              await env.DB.prepare(sql).bind(...allBinds).run();
            }
            updated++;
            continue;
          }
          const salt = randomSalt();
          const hash = await hashPassword(String(r.password || "Vnpt@2026"), salt);
          if (kind === "staff") {
            // Nhan su moi: role suy tu chuc danh + SubAdmin (subadmin import thi khong duoc cap subadmin/admin)
            const newRole = isAdmin ? staffRoleFrom(impChucDanh, impSubAdmin) : (impChucDanh === "Lãnh đạo đơn vị" ? "leader" : "staff");
            const newModules = impModules || defaultModulesForRole(newRole);
            await env.DB.prepare(
              "INSERT INTO nguoi_dung (ho_ten, username, password_hash, salt, role, ma_nhan_vien, chuc_danh, don_vi_id, can_import, modules) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
              .bind(hoTen, username, hash, salt, newRole, impMaNv, impChucDanh, donViOk ? donViId : null, impCanImport, newModules)
              .run();
          } else {
            // Diem ban moi: luon la user, khong co quyen import, mac dinh 4 module
            await env.DB.prepare(
              "INSERT INTO nguoi_dung (ma_kenh, ho_ten, username, password_hash, salt, role, so_eload, so_vi, ten_nhan_vien, sdt_nhan_vien, ma_hrm, don_vi_id, leader_id, loai_kenh, can_import, modules, lat, lng) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
            )
              .bind(
                toText(r.ma_kenh), hoTen, username, hash, salt,
                "user",
                toText(r.so_eload), toText(r.so_vi), toText(r.ten_nhan_vien), toText(r.sdt_nhan_vien), toText(r.ma_hrm), donViOk ? donViId : null, leaderOk ? leaderId : null, impLoaiKenh, 0,
                JSON.stringify(DEFAULT_MODULES),
                latOk ? impLat : null, lngOk ? impLng : null
              )
              .run();
          }
          created++;
        }
        return json({ ok: true, created, updated, skipped, errors: errors.slice(0, 50), warnings: warnings.slice(0, 50) });
      }
      const userMatch = path.match(/^\/api\/users\/(\d+)$/);
      if (userMatch && method === "PUT") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen sua nguoi dung", 403);
        const b = await readBody(request);
        const kind = b.kind === "staff" ? "staff" : "channel";
        const needKey = kind === "staff" ? "staff" : "users";
        if (!hasModule(me, needKey)) return err("Tai khoan khong co quyen su dung module nay", 403);
        const uid = Number(userMatch[1]);
        const cur = await env.DB.prepare("SELECT role, can_import, modules, chuc_danh FROM nguoi_dung WHERE id = ?").bind(uid).first();
        if (!cur) return err("Khong tim thay nguoi dung", 404);
        // Khong cho sua tai khoan khac module (kenh ban <-> nhan su)
        if (kind === "channel" && cur.role !== "user") return err("Tai khoan nay thuoc module Quan ly nguoi dung", 422);
        if (kind === "staff" && cur.role === "user") return err("Tai khoan nay thuoc module Quan ly kenh ban", 422);
        if (!toText(b.ho_ten)) return err("Thieu ho ten", 422);
        let newRole = cur.role, newCanImport = cur.can_import, newModules = cur.modules;
        let newMaNv = null, newChucDanh = null; // null = khong doi cot nay
        if (kind === "staff") {
          newMaNv = toText(b.ma_nhan_vien);
          newChucDanh = ("chuc_danh" in b) ? toText(b.chuc_danh) : (cur.chuc_danh || "");
          if (newChucDanh && !CHUC_DANH_LIST.includes(newChucDanh)) return err("Chuc danh khong hop le", 422);
          const subAdm = ("subadmin" in b) ? !!b.subadmin : cur.role === "subadmin";
          if (isAdmin) {
            newRole = staffRoleFrom(newChucDanh, subAdm);
            newCanImport = b.can_import ? 1 : 0;
            if (Array.isArray(b.modules)) newModules = JSON.stringify(b.modules.filter((k) => MODULE_KEYS.includes(k)));
          } else {
            // SubAdmin khong duoc nang/hạ loai tai khoan admin/subadmin, khong doi quyen import/module
            if (cur.role === "admin" || cur.role === "subadmin") newRole = cur.role;
            else newRole = newChucDanh === "Lãnh đạo đơn vị" ? "leader" : "staff";
          }
          if (uid === me.id && newRole !== me.role) return err("Khong the tu doi loai tai khoan cua chinh minh", 422);
        } else {
          newRole = "user";
          if (isAdmin && Array.isArray(b.modules)) newModules = JSON.stringify(b.modules.filter((k) => MODULE_KEYS.includes(k)));
        }
        const latP = parseCoordField(b.lat, -90, 90);
        if (latP.error) return err("Vi do diem ban khong hop le (tu -90 den 90)", 422);
        const lngP = parseCoordField(b.lng, -180, 180);
        if (lngP.error) return err("Kinh do diem ban khong hop le (tu -180 den 180)", 422);
        let newLeaderId = null;
        if (b.leader_id) {
          const ld = await env.DB.prepare("SELECT id FROM nguoi_dung WHERE id = ? AND role = 'leader'").bind(Number(b.leader_id)).first();
          if (!ld) return err("Lanh dao phu trach khong ton tai hoac khong phai tai khoan Lanh dao don vi", 422);
          newLeaderId = ld.id;
        }
        const newLoaiKenh = normLoaiKenh(b.loai_kenh);
        if (toText(b.loai_kenh) && !newLoaiKenh) return err("Loai kenh ban khong hop le (DUQ/DBL/GARA/DDV)", 422);
        const sets = ["ho_ten = ?", "don_vi_id = ?", "active = ?", "role = ?", "can_import = ?", "modules = ?"];
        const binds = [toText(b.ho_ten), b.don_vi_id ? Number(b.don_vi_id) : null, b.active === false ? 0 : 1, newRole, newCanImport, newModules];
        if (kind === "staff") {
          sets.push("ma_nhan_vien = ?", "chuc_danh = ?"); binds.push(newMaNv, newChucDanh);
        } else {
          sets.push("ma_kenh = ?", "so_eload = ?", "so_vi = ?", "ten_nhan_vien = ?", "sdt_nhan_vien = ?", "ma_hrm = ?",
            "leader_id = ?", "loai_kenh = ?", "lat = ?", "lng = ?");
          binds.push(toText(b.ma_kenh), toText(b.so_eload), toText(b.so_vi), toText(b.ten_nhan_vien),
            toText(b.sdt_nhan_vien), toText(b.ma_hrm), newLeaderId, newLoaiKenh, latP.val, lngP.val);
        }
        await env.DB.prepare("UPDATE nguoi_dung SET " + sets.join(", ") + " WHERE id = ?").bind(...binds, uid).run();
        if (b.password) {
          const salt = randomSalt();
          const hash = await hashPassword(String(b.password), salt);
          await env.DB.prepare("UPDATE nguoi_dung SET password_hash = ?, salt = ? WHERE id = ?")
            .bind(hash, salt, uid)
            .run();
        }
        return json({ ok: true });
      }
      if (userMatch && method === "DELETE") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen xoa nguoi dung", 403);
        if (!(hasModule(me, "users") || hasModule(me, "staff"))) return err("Tai khoan khong co quyen su dung module nay", 403);
        if (Number(userMatch[1]) === me.id) return err("Khong the tu xoa tai khoan dang dang nhap", 422);
        const leadRef = await env.DB.prepare("SELECT COUNT(*) AS c FROM nguoi_dung WHERE leader_id = ?").bind(Number(userMatch[1])).first();
        if (leadRef && leadRef.c > 0) return err("Khong the xoa — nguoi dung nay dang la Lanh dao phu trach cua " + leadRef.c + " diem ban. Hay gan lai lanh dao phu trach truoc khi xoa.", 422);
        await env.DB.prepare("DELETE FROM nguoi_dung WHERE id = ?").bind(Number(userMatch[1])).run();
        return json({ ok: true });
      }
      // ---- Xoa nhieu nguoi dung cung luc (theo danh sach da danh dau) ----
      if (path === "/api/users/bulk-delete" && method === "POST") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen xoa nguoi dung", 403);
        if (!(hasModule(me, "users") || hasModule(me, "staff"))) return err("Tai khoan khong co quyen su dung module nay", 403);
        const b = await readBody(request);
        const ids = [...new Set((Array.isArray(b.ids) ? b.ids : []).map(Number).filter((n) => n > 0))];
        if (!ids.length) return err("Chua chon nguoi dung nao de xoa", 422);
        let deleted = 0;
        const skipped = [];
        for (const id of ids) {
          if (id === me.id) { skipped.push({ id, reason: "Khong the tu xoa tai khoan dang dang nhap" }); continue; }
          const leadRef = await env.DB.prepare("SELECT COUNT(*) AS c FROM nguoi_dung WHERE leader_id = ?").bind(id).first();
          if (leadRef && leadRef.c > 0) { skipped.push({ id, reason: "Dang la Lanh dao phu trach cua " + leadRef.c + " diem ban — hay gan lai lanh dao phu trach truoc khi xoa" }); continue; }
          const r = await env.DB.prepare("DELETE FROM nguoi_dung WHERE id = ?").bind(id).run();
          if ((r.meta.changes || 0) > 0) deleted++;
          else skipped.push({ id, reason: "Khong tim thay nguoi dung" });
        }
        return json({ ok: true, deleted, skipped });
      }
      // ---- Reset mat khau nhan su ve mac dinh Vnpt@2026 (module Quan ly nguoi dung) ----
      const resetMatch = path.match(/^\/api\/users\/(\d+)\/reset-password$/);
      if (resetMatch && method === "POST") {
        if (!canManageUsers) return err("Chi admin/subadmin moi co quyen reset mat khau", 403);
        if (!hasModule(me, "staff")) return err("Tai khoan khong co quyen su dung module Quan ly nguoi dung", 403);
        const rid = Number(resetMatch[1]);
        if (rid === me.id) return err("Khong the reset mat khau chinh minh tai day — doi mat khau trong module Cai dat", 422);
        const target = await env.DB.prepare("SELECT id, role FROM nguoi_dung WHERE id = ?").bind(rid).first();
        if (!target) return err("Khong tim thay nguoi dung", 404);
        if (target.role === "user") return err("Tai khoan diem ban duoc quan ly trong module Quan ly kenh ban", 422);
        const salt = randomSalt();
        const hash = await hashPassword("Vnpt@2026", salt);
        await env.DB.prepare("UPDATE nguoi_dung SET password_hash = ?, salt = ? WHERE id = ?").bind(hash, salt, rid).run();
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
        // money_col / time_col KHONG bat buoc nua (loai du lieu ban hang co the
        // de "Khong dung") — cac loai thieu 2 cot nay tu dong khong lot vao
        // Dashboard/Bao cao chi tra hoa hong (aggregateSummary da loc san).
        for (const rc of ["eload_col"]) {
          if (!b[rc] || !keys.has(b[rc])) return err("Chua chon cot vai tro bat buoc: " + rc, 422);
        }
        const salesKind = ["doanh_thu", "san_luong"].includes(b.sales_kind) ? b.sales_kind : "";
        for (const rc of ["money_col", "time_col", "time_fallback_col", "vi_col", "sub_col", "pkg_col", "trans_col", "status_col", "reason_col", "key_col", "kenh_col", "sales_unit_col", "sales_eload_col", "sales_kenh_col", "sales_price_col", "sales_qty_col", "sales_result_col", "sales_subtype_col"]) {
          if (b[rc] && !keys.has(b[rc])) return err("Cot vai tro khong nam trong danh sach cot: " + rc, 422);
        }
        const exists = (await getDataTypes(env)).some((t) => t.code === code || t.prefix === code);
        if (exists) return err("Ma loai du lieu da ton tai: " + code, 422);
        const cleanCols = columns.map((c) => ({
          key: String(c.key), label: toText(c.label) || String(c.key),
          type: ["money", "number", "date"].includes(c.type) ? c.type : "text",
        }));
        const r = await env.DB.prepare(
          "INSERT INTO loai_du_lieu (code, name, prefix, fmt, columns_json, money_col, time_col, time_fallback_col, eload_col, vi_col, sub_col, pkg_col, trans_col, status_col, reason_col, key_col, kenh_col, sales_unit_col, sales_eload_col, sales_kenh_col, sales_price_col, sales_qty_col, sales_result_col, sales_subtype_col, sales_kind, builtin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)"
        )
          .bind(code, name, code, fmt, JSON.stringify(cleanCols),
            b.money_col, b.time_col, b.time_fallback_col || "", b.eload_col, b.vi_col || "",
            b.sub_col || "", b.pkg_col || "", b.trans_col || "", b.status_col || "", b.reason_col || "", b.key_col || "", b.kenh_col || "",
            b.sales_unit_col || "", b.sales_eload_col || "", b.sales_kenh_col || "", b.sales_price_col || "", b.sales_qty_col || "",
            b.sales_result_col || "", b.sales_subtype_col || "", salesKind)
          .run();
        return json({ ok: true, id: r.meta.last_row_id, code });
      }
      // Sua loai du lieu TU TAO (admin): doi duoc ten, danh sach cot va cac
      // cot vai tro. Khong doi duoc ma (dinh danh), dinh dang ten bang
      // (fmt) va khong sua duoc loai mac dinh — doi fmt sau khi da co bang
      // thang se lam mo coi cac bang cu.
      const dtPutMatch = path.match(/^\/api\/datatypes\/(\d+)$/);
      if (dtPutMatch && method === "PUT") {
        if (!isAdmin) return err("Chi admin moi co quyen sua loai du lieu", 403);
        const b = await readBody(request);
        const row = await env.DB.prepare("SELECT * FROM loai_du_lieu WHERE id = ?").bind(Number(dtPutMatch[1])).first();
        if (!row) return err("Loai du lieu khong ton tai", 404);
        if (row.builtin) return err("Khong sua duoc loai du lieu mac dinh", 403);
        const name = toText(b.name);
        const columns = Array.isArray(b.columns) ? b.columns : [];
        if (!name) return err("Thieu ten loai du lieu", 422);
        if (!columns.length) return err("Loai du lieu phai co it nhat 1 cot", 422);
        const keys = new Set();
        for (const c of columns) {
          if (!/^[a-z][a-z0-9_]*$/.test(String(c.key || ""))) return err("Khoa cot khong hop le: " + (c.key || ""), 422);
          if (keys.has(c.key)) return err("Trung khoa cot: " + c.key, 422);
          keys.add(c.key);
        }
        for (const rc of ["eload_col"]) {
          if (!b[rc] || !keys.has(b[rc])) return err("Chua chon cot vai tro bat buoc: " + rc, 422);
        }
        const salesKind = ["doanh_thu", "san_luong"].includes(b.sales_kind) ? b.sales_kind : "";
        for (const rc of ["money_col", "time_col", "time_fallback_col", "vi_col", "sub_col", "pkg_col", "trans_col", "status_col", "reason_col", "key_col", "kenh_col", "sales_unit_col", "sales_eload_col", "sales_kenh_col", "sales_price_col", "sales_qty_col", "sales_result_col", "sales_subtype_col"]) {
          if (b[rc] && !keys.has(b[rc])) return err("Cot vai tro khong nam trong danh sach cot: " + rc, 422);
        }
        const cleanCols = columns.map((c) => ({
          key: String(c.key), label: toText(c.label) || String(c.key),
          type: ["money", "number", "date"].includes(c.type) ? c.type : "text",
        }));
        await env.DB.prepare(
          "UPDATE loai_du_lieu SET name = ?, columns_json = ?, money_col = ?, time_col = ?, time_fallback_col = ?, eload_col = ?, vi_col = ?, sub_col = ?, pkg_col = ?, trans_col = ?, status_col = ?, reason_col = ?, key_col = ?, kenh_col = ?, sales_unit_col = ?, sales_eload_col = ?, sales_kenh_col = ?, sales_price_col = ?, sales_qty_col = ?, sales_result_col = ?, sales_subtype_col = ?, sales_kind = ? WHERE id = ?"
        )
          .bind(name, JSON.stringify(cleanCols),
            b.money_col, b.time_col, b.time_fallback_col || "", b.eload_col, b.vi_col || "",
            b.sub_col || "", b.pkg_col || "", b.trans_col || "", b.status_col || "", b.reason_col || "", b.key_col || "", b.kenh_col || "",
            b.sales_unit_col || "", b.sales_eload_col || "", b.sales_kenh_col || "", b.sales_price_col || "", b.sales_qty_col || "",
            b.sales_result_col || "", b.sales_subtype_col || "", salesKind, row.id)
          .run();
        return json({ ok: true, code: row.code });
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
      // Danh sach diem ban cho bo loc "Theo diem ban" trong Bao cao thong ke.
      // Admin/subadmin: toan bo diem ban; lanh dao (va chuyen vien tuong
      // duong): diem ban trong cay don vi cua minh; con lai: chi chinh minh.
      if (path === "/api/pos-list" && method === "GET") {
        if (!hasModule(me, "reports")) return err("Tai khoan khong co quyen xem bao cao", 403);
        let sql, binds;
        if (isPrivileged) {
          sql = "SELECT u.id, u.ma_kenh, u.ho_ten, u.username, u.don_vi_id, d.ten_don_vi AS don_vi_ten FROM nguoi_dung u LEFT JOIN don_vi d ON d.id = u.don_vi_id WHERE u.role = 'user' ORDER BY u.ho_ten";
          binds = [];
        } else if (isLeaderLike && me.don_vi_id) {
          sql = unitSubtreeCTE() + " SELECT u.id, u.ma_kenh, u.ho_ten, u.username, u.don_vi_id, d.ten_don_vi AS don_vi_ten FROM nguoi_dung u LEFT JOIN don_vi d ON d.id = u.don_vi_id WHERE u.role = 'user' AND u.don_vi_id IN (SELECT id FROM subtree) ORDER BY u.ho_ten";
          binds = [me.don_vi_id];
        } else {
          sql = "SELECT u.id, u.ma_kenh, u.ho_ten, u.username, u.don_vi_id, d.ten_don_vi AS don_vi_ten FROM nguoi_dung u LEFT JOIN don_vi d ON d.id = u.don_vi_id WHERE u.id = ?";
          binds = [me.id];
        }
        const res = await env.DB.prepare(sql).bind(...binds).all();
        return json({ ok: true, list: res.results || [] });
      }
      if (path === "/api/reports/summary" && method === "GET") {
        if (!hasModule(me, "reports") && !hasModule(me, "dashboard")) return err("Tai khoan khong co quyen xem bao cao", 403);
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        const group = url.searchParams.get("group") || "day";
        const loai = (url.searchParams.get("loai") || "ALL").toUpperCase();
        const statusFilter = parseStatusFilter(url.searchParams.get("trang_thai"));
        const r = await resolveScopeUnit(env, me, isLeaderLike, isPrivileged, url.searchParams.get("don_vi"));
        if (!r.ok) return err(r.msg, r.code);
        const pr = await resolvePosUser(env, me, isPrivileged, isLeaderLike, url.searchParams.get("diem_ban"));
        if (!pr.ok) return err(pr.msg, pr.code);
        const d = await aggregateSummary(env, me, isPrivileged, isUnitScoped, { from, to, group, loai, scopeUnit: r.unit, statusFilter, posUser: pr.pos });
        return json({ ok: true, ...d, pos: pr.pos ? { id: pr.pos.id, ho_ten: pr.pos.ho_ten, username: pr.pos.username } : null });
      }
      // Tong hop theo don vi: moi dong la tong so lieu cua cac diem ban thuoc
      // don vi do (map qua so_eload/so_vi/ma_kenh/ma_hrm-sdt). Admin/subadmin
      // thay toan bo don vi; lanh dao chi thay cac don vi trong cay cua minh.
      if (path === "/api/reports/by-unit" && method === "GET") {
        if (!hasModule(me, "reports")) return err("Tai khoan khong co quyen xem bao cao", 403);
        if (!isPrivileged && !isLeaderLike) return err("Chi admin/subadmin/lanh dao moi xem duoc bao cao theo don vi", 403);
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        const loai = (url.searchParams.get("loai") || "ALL").toUpperCase();
        const statusFilter = parseStatusFilter(url.searchParams.get("trang_thai"));
        const pr = await resolvePosUser(env, me, isPrivileged, isLeaderLike, url.searchParams.get("diem_ban"));
        if (!pr.ok) return err(pr.msg, pr.code);
        const posUser = pr.pos;
        let units;
        if (posUser && posUser.don_vi_id) {
          // Loc theo diem ban: chi hien dong don vi cua diem ban do
          units = (await env.DB.prepare("SELECT id, ma_don_vi, ten_don_vi, parent_id FROM don_vi WHERE id = ?").bind(posUser.don_vi_id).all()).results || [];
        } else if (isPrivileged) {
          units = (await env.DB.prepare("SELECT id, ma_don_vi, ten_don_vi, parent_id FROM don_vi ORDER BY ten_don_vi").all()).results || [];
        } else {
          units = (await env.DB.prepare(unitSubtreeCTE() + " SELECT d.id, d.ma_don_vi, d.ten_don_vi, d.parent_id FROM don_vi d WHERE d.id IN (SELECT id FROM subtree) ORDER BY d.ten_don_vi").bind(me.don_vi_id).all()).results || [];
        }
        const out = [];
        for (const u of units) {
          const d = await aggregateSummary(env, me, isPrivileged, isUnitScoped, { from, to, group: "month", loai, scopeUnit: u.id, statusFilter, posUser });
          out.push({ don_vi_id: u.id, ma_don_vi: u.ma_don_vi, ten_don_vi: u.ten_don_vi, so_giao_dich: d.tong_giao_dich, tong_tien: d.tong_tien });
        }
        return json({ ok: true, units: out, pos: posUser ? { id: posUser.id, ho_ten: posUser.ho_ten, username: posUser.username } : null });
      }
      // Dashboard ban hang: tong hop phat trien thue bao di dong + doanh thu ban
      // goi di dong phat trien moi (truoc thue = gia goi / 1,1) theo don vi va
      // theo diem ban. Loai du lieu do admin thiet ke trong module Cai dat
      // (map 5 cot sales_*: ten don vi, so eload, ma kenh, gia goi, so luong).
      // NGUYEN TAC MAP: theo don vi -> can cu ten don vi trong du lieu; theo
      // diem ban -> can cu ma kenh hoac so eload; chi tinh cac thue bao do
      // tai khoan Eload cua diem ban (role='user') phat trien.
      // Ke hoach kinh doanh theo thang + don vi: PSSL / san luong thue bao / doanh thu.
      // don_vi_id = 0 la muc "Toan tinh" (tuong thich du lieu ke hoach PSSL cu).
      const KEHOACH_DDL = "CREATE TABLE IF NOT EXISTS ke_hoach (thang TEXT NOT NULL, don_vi_id INTEGER NOT NULL DEFAULT 0, loai TEXT NOT NULL, so_luong REAL NOT NULL DEFAULT 0, updated_by TEXT, updated_at TEXT, PRIMARY KEY (thang, don_vi_id, loai))";
      async function ensureKeHoach(env) {
        await env.DB.prepare(KEHOACH_DDL).run();
        try {
          const old = await env.DB.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='ke_hoach_pssl'").first();
          if (old) {
            await env.DB.prepare("INSERT OR IGNORE INTO ke_hoach (thang, don_vi_id, loai, so_luong, updated_by, updated_at) SELECT thang, 0, 'pssl', so_luong, updated_by, updated_at FROM ke_hoach_pssl").run();
            await env.DB.prepare("DROP TABLE ke_hoach_pssl").run();
          }
        } catch (e) { /* bo qua */ }
      }
      const KEHOACH_LOAI = ["pssl", "subs", "revenue"];
      if (path === "/api/ke-hoach" && method === "GET") {
        if (!hasModule(me, "salesdash") && !hasModule(me, "import")) return err("Tai khoan khong co quyen xem ke hoach", 403);
        const thang = String(url.searchParams.get("thang") || "").trim();
        const loai = String(url.searchParams.get("loai") || "").trim();
        if (!/^\d{4}-\d{2}$/.test(thang)) return err("Thang khong hop le (YYYY-MM)", 422);
        if (loai && !KEHOACH_LOAI.includes(loai)) return err("Loai ke hoach khong hop le", 422);
        await ensureKeHoach(env);
        const binds = loai ? [thang, loai] : [thang];
        const r = await env.DB.prepare("SELECT don_vi_id, loai, so_luong FROM ke_hoach WHERE thang = ?" + (loai ? " AND loai = ?" : "")).bind(...binds).all();
        return json({ ok: true, thang, plans: r.results || [] });
      }
      if (path === "/api/ke-hoach" && method === "PUT") {
        if (!isAdmin) return err("Chi admin moi duoc giao ke hoach", 403);
        const b = await readBody(request);
        const thang = String(b.thang || "").trim();
        const loai = String(b.loai || "").trim();
        const items = Array.isArray(b.items) ? b.items : [];
        if (!/^\d{4}-\d{2}$/.test(thang)) return err("Thang khong hop le (YYYY-MM)", 422);
        if (!KEHOACH_LOAI.includes(loai)) return err("Loai ke hoach khong hop le", 422);
        await ensureKeHoach(env);
        const stmt = env.DB.prepare("INSERT INTO ke_hoach (thang, don_vi_id, loai, so_luong, updated_by, updated_at) VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(thang, don_vi_id, loai) DO UPDATE SET so_luong = excluded.so_luong, updated_by = excluded.updated_by, updated_at = excluded.updated_at");
        const batch = items.map((it) => stmt.bind(thang, Math.max(0, Math.round(Number(it.don_vi_id) || 0)), loai, Math.max(0, Number(it.so_luong) || 0), me.username || "", saigonNow()));
        if (batch.length) await env.DB.batch(batch);
        return json({ ok: true, thang, loai, saved: batch.length });
      }
      // Dashboard ban hang kieu dieu hanh (moi):
      // - Tu dong tong hop TAT CA loai du lieu ban hang (doanh thu / san luong), khong can chon.
      // - Loai bo cung cac giao dich co ket qua "Dang ky khong thanh cong".
      // - Ky danh gia: theo thang (ky=thang) hoac theo nam (ky=nam).
      // - PSSL = diem ban co phat sinh san luong trong ky: co dong du lieu ban hang
      //   (bat ky loai nao) duoc map ve Eload cua diem ban.
      if (path === "/api/sales-overview" && method === "GET") {
        if (!hasModule(me, "salesdash")) return err("Tai khoan khong co quyen xem Dashboard ban hang", 403);
        const types = await getDataTypes(env);
        const stypes = types.filter((x) => {
          if (x.sales_kind === "san_luong") return x.sales_unit_col && x.sales_eload_col;
          return (x.sales_kind === "doanh_thu" || !x.sales_kind) && x.sales_unit_col && x.sales_eload_col && x.sales_price_col;
        });
        if (!stypes.length) return err("Chua co loai du lieu nao duoc khai bao dung cho Dashboard ban hang. Vao Quan ly du lieu dau vao > Quan ly loai du lieu de thiet lap.", 422);
        const ky = url.searchParams.get("ky") === "nam" ? "nam" : "thang";
        const nowS = saigonNow();
        let thang = String(url.searchParams.get("thang") || "").trim();
        if (!/^\d{4}-\d{2}$/.test(thang)) thang = nowS.slice(0, 7);
        let nam = parseInt(url.searchParams.get("nam"), 10);
        if (!nam || nam < 2000 || nam > 2100) nam = Number(nowS.slice(0, 4));
        const months = [];
        let curMonths, prevMonths, c2Months, cmp1_label, cmp2_label, trendMonths, periodLabel;
        if (ky === "nam") {
          for (let m = 1; m <= 12; m++) months.push((nam - 1) + "-" + String(m).padStart(2, "0"));
          for (let m = 1; m <= 12; m++) months.push(nam + "-" + String(m).padStart(2, "0"));
          curMonths = months.slice(12); prevMonths = months.slice(0, 12); c2Months = [];
          cmp1_label = "vs năm " + (nam - 1); cmp2_label = null;
          trendMonths = curMonths; periodLabel = "năm " + nam;
        } else {
          let y = Number(thang.slice(0, 4)), m = Number(thang.slice(5, 7));
          for (let i = 11; i >= 0; i--) { let mm = m - i, yy = y; while (mm <= 0) { mm += 12; yy--; } months.push(yy + "-" + String(mm).padStart(2, "0")); }
          const T = months[13];
          curMonths = [T]; prevMonths = [months[12]]; c2Months = [months[1]];
          cmp1_label = "vs tháng trước"; cmp2_label = "vs cùng kỳ năm trước";
          trendMonths = months; periodLabel = "tháng " + Number(T.slice(5, 7)) + "/" + T.slice(0, 4);
        }
        const monthSet = new Set(months);
        const normE = (s) => String(s == null ? "" : s).trim().toUpperCase().replace(/\s+/g, "");
        const posRows = (await env.DB.prepare(
          "SELECT u.id, u.ho_ten, u.ma_kenh, u.so_eload, u.don_vi_id, u.loai_kenh, d.ten_don_vi AS don_vi_ten " +
          "FROM nguoi_dung u LEFT JOIN don_vi d ON d.id = u.don_vi_id " +
          "WHERE u.role = 'user' AND u.so_eload IS NOT NULL AND TRIM(u.so_eload) != ''"
        ).all()).results || [];
        const posByEload = {};
        for (const pr2 of posRows) { const e = normE(pr2.so_eload); if (e && !posByEload[e]) posByEload[e] = pr2; }
        const normU = (s) => String(s == null ? "" : s).trim().toLowerCase()
          .normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/đ/g, "d")
          .replace(/[–—−‐‒]/g, "-").replace(/\s+/g, " ").replace(/\s*-\s*/g, "-");
        const allUnits = (await env.DB.prepare("SELECT id, ten_don_vi FROM don_vi").all()).results || [];
        const unitNameToId = {};
        for (const u of allUnits) unitNameToId[normU(u.ten_don_vi)] = u.id;
        let scopeUnitIds = null; // null = toan tinh (admin/subadmin)
        let scopeNames = null;
        const leaderScoped = isLeaderLike && me.don_vi_id;
        if (leaderScoped) {
          const urs = (await env.DB.prepare(unitSubtreeCTE() + " SELECT d.id, d.ten_don_vi FROM don_vi d WHERE d.id IN (SELECT id FROM subtree)").bind(me.don_vi_id).all()).results || [];
          scopeUnitIds = urs.map((u) => u.id);
          scopeNames = new Set(urs.map((u) => normU(u.ten_don_vi)));
        } else if (!isPrivileged) {
          scopeUnitIds = me.don_vi_id ? [me.don_vi_id] : [];
        }
        const ownOnly = !isPrivileged && !leaderScoped;
        const meEload = normE(me.so_eload || "");
        const fStList = url.searchParams.getAll("loai_tb").map((s) => String(s || "").trim());
        const isDuqPos = (p) => normLoaiKenh(p.loai_kenh) === "DUQ";
        // Quy mo kenh DUQ theo pham vi
        let scaleDuq = 0;
        const duqPosIds = [];
        for (const e in posByEload) {
          const p = posByEload[e];
          if (!isDuqPos(p)) continue;
          if (scopeUnitIds !== null && !scopeUnitIds.includes(p.don_vi_id)) continue;
          if (ownOnly && e !== meEload) continue;
          scaleDuq++;
          duqPosIds.push(p.id);
        }
        const newMonthAgg = () => ({ subs: 0, revenue: 0, pssl: new Set(), units: {}, pos: {} });
        const perMonth = {};
        const stSet = new Set();
        let hasSubtypeCol = false;
        let hasSubsSrc = false, hasRevSrc = false;
        for (const t of stypes) {
          const needPrice = t.sales_kind !== "san_luong";
          // Quy tac tong hop theo dung yeu cau: thue bao PTM chi tu loai "san_luong";
          // doanh thu chi tu loai "doanh_thu" (va loai chua phan kind co cot gia).
          const isSubsSrc = t.sales_kind === "san_luong";
          const isRevSrc = !isSubsSrc;
          if (isSubsSrc) hasSubsSrc = true; else hasRevSrc = true;
          const needCols = [t.sales_unit_col, t.sales_eload_col];
          if (t.sales_price_col) needCols.push(t.sales_price_col);
          if (t.sales_kenh_col) needCols.push(t.sales_kenh_col);
          if (t.sales_qty_col) needCols.push(t.sales_qty_col);
          if (t.sales_result_col) needCols.push(t.sales_result_col);
          if (t.sales_subtype_col) { needCols.push(t.sales_subtype_col); hasSubtypeCol = true; }
          const tables = await listMonthlyTables(env, t.prefix);
          for (const tbl of tables) {
            const mk = tableMonthKey(tbl);
            if (!mk || !monthSet.has(mk)) continue;
            const cols = (await env.DB.prepare("PRAGMA table_info(" + tbl + ")").all()).results || [];
            const cn = new Set(cols.map((c) => c.name));
            if (!needCols.every((c) => cn.has(c))) continue;
            // Quy tac TNTTTB: tim cot loai_don / vai_tro (khong phan biet hoa/thuong)
            let loaiDonCol = null, vaiTroCol = null;
            if (isSubsSrc) {
              for (const c of cn) {
                const cl = String(c).toLowerCase();
                if (cl === "loai_don") loaiDonCol = c;
                else if (cl === "vai_tro" || cl === "vaitro") vaiTroCol = c;
              }
            }
            const rows = (await env.DB.prepare("SELECT * FROM " + tbl).all()).results || [];
            for (const r of rows) {
              const e = normE(r[t.sales_eload_col]);
              const pos = posByEload[e];
              if (!pos) continue;
              const rawU = String(r[t.sales_unit_col] == null ? "" : r[t.sales_unit_col]).trim();
              const nu = normU(rawU);
              if (scopeNames && !scopeNames.has(nu)) continue;
              if (ownOnly && e !== meEload) continue;
              const kq = t.sales_result_col ? String(r[t.sales_result_col] == null ? "" : r[t.sales_result_col]).trim() : "";
              // Loai bo cung giao dich "Dang ky khong thanh cong"
              if (kq && kq.toLowerCase() === "đăng ký không thành công") continue;
              const st = t.sales_subtype_col ? String(r[t.sales_subtype_col] == null ? "" : r[t.sales_subtype_col]).trim() : "";
              if (t.sales_subtype_col) stSet.add(st || "(Trống)");
              if (fStList.length && !fStList.includes(st)) continue;
              // Quy tac bang TNTTTB: chi dem san luong khi loai_don khong null/rong
              // (chi ap dung khi bang co cot loai_don).
              if (isSubsSrc && loaiDonCol) {
                const ld = r[loaiDonCol];
                if (ld == null || String(ld).trim() === "") continue;
              }
              // Quy tac TNTTTB: chi dem san luong khi Vai tro = DUQ.
              // Diem kenh khac van tinh PSSL, chi khong cong vao tong san luong.
              let isDuqRow = true;
              if (isSubsSrc && vaiTroCol) isDuqRow = normLoaiKenh(r[vaiTroCol]) === "DUQ";
              const price = toNumber(r[t.sales_price_col]);
              let qty = t.sales_qty_col ? toNumber(r[t.sales_qty_col]) : 0;
              if (!qty || qty <= 0) qty = 1;
              const subAdd = isSubsSrc && isDuqRow ? qty : 0;
              const revAdd = isRevSrc && needPrice ? price / 1.1 * qty : 0;
              const pm = perMonth[mk] || (perMonth[mk] = newMonthAgg());
              pm.subs += subAdd; pm.revenue += revAdd; pm.pssl.add(e);
              const u = pm.units[nu] || (pm.units[nu] = { name: rawU || "(Chưa xác định)", subs: 0, revenue: 0, pssl: new Set() });
              u.subs += subAdd; u.revenue += revAdd; u.pssl.add(e);
              const pp = pm.pos[e] || (pm.pos[e] = { subs: 0, revenue: 0 });
              pp.subs += subAdd; pp.revenue += revAdd;
            }
          }
        }
        const aggMonths = (mks) => {
          const a = newMonthAgg();
          for (const mk of mks) {
            const pm = perMonth[mk]; if (!pm) continue;
            a.subs += pm.subs; a.revenue += pm.revenue;
            for (const e of pm.pssl) a.pssl.add(e);
            for (const nu in pm.units) {
              const s = pm.units[nu];
              const u = a.units[nu] || (a.units[nu] = { name: s.name, subs: 0, revenue: 0, pssl: new Set() });
              u.subs += s.subs; u.revenue += s.revenue;
              for (const e of s.pssl) u.pssl.add(e);
            }
            for (const e in pm.pos) {
              const s = pm.pos[e];
              const pp = a.pos[e] || (a.pos[e] = { subs: 0, revenue: 0 });
              pp.subs += s.subs; pp.revenue += s.revenue;
            }
          }
          return a;
        };
        const cur = aggMonths(curMonths), prev = aggMonths(prevMonths), c2 = aggMonths(c2Months);
        const pct = (a, b) => b > 0 ? Math.round((a - b) / b * 1000) / 10 : null;
        // Ke hoach
        await ensureKeHoach(env);
        const planRows = ((await env.DB.prepare("SELECT thang, don_vi_id, loai, so_luong FROM ke_hoach").all()).results || []);
        const planSum = (mks, loai) => {
          let total = 0, hasUnit = false;
          for (const mk of mks) {
            const rows = planRows.filter((r) => r.thang === mk && r.loai === loai);
            const urows = rows.filter((r) => r.don_vi_id !== 0 && (scopeUnitIds === null || scopeUnitIds.includes(r.don_vi_id)));
            if (urows.length) { hasUnit = true; total += urows.reduce((a, r) => a + (Number(r.so_luong) || 0), 0); }
          }
          if (!hasUnit && scopeUnitIds === null) {
            for (const mk of mks) {
              const g = planRows.find((r) => r.thang === mk && r.loai === loai && r.don_vi_id === 0);
              if (g) total += Number(g.so_luong) || 0;
            }
          }
          return total;
        };
        const unitPlan = (nu, mks, loai) => {
          const uid = unitNameToId[nu];
          if (!uid) return 0;
          let s = 0;
          for (const mk of mks) {
            const r = planRows.find((x) => x.thang === mk && x.loai === loai && x.don_vi_id === uid);
            if (r) s += Number(r.so_luong) || 0;
          }
          return s;
        };
        const khPssl = planSum(curMonths, "pssl"), khSubs = planSum(curMonths, "subs"), khRev = planSum(curMonths, "revenue");
        const psslCount = cur.pssl.size, psslPrev = prev.pssl.size;
        const psslDuq = [...cur.pssl].filter((e) => { const p = posByEload[e]; return p && isDuqPos(p); }).length;
        const psslDuqPrev = [...prev.pssl].filter((e) => { const p = posByEload[e]; return p && isDuqPos(p); }).length;
        const tyleDuq = scaleDuq > 0 ? Math.round(psslDuq / scaleDuq * 1000) / 10 : null;
        const tyleDuqPrev = scaleDuq > 0 ? Math.round(psslDuqPrev / scaleDuq * 1000) / 10 : null;
        // Cham soc kenh DUQ theo don vi trong ky
        let careByUnit = [];
        try {
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS dot_cham_soc (id INTEGER PRIMARY KEY AUTOINCREMENT, ten_dot TEXT NOT NULL, ghi_chu TEXT, nguoi_tao_id INTEGER, nguoi_tao_ten TEXT, created_at TEXT)").run();
          await env.DB.prepare("CREATE TABLE IF NOT EXISTS cham_soc (id INTEGER PRIMARY KEY AUTOINCREMENT, dot_id INTEGER NOT NULL, pos_user_id INTEGER NOT NULL, caregiver_id INTEGER, caregiver_ten TEXT, thoi_gian TEXT, lat REAL, lng REAL, khoang_cach_m REAL, anh_key TEXT, anh_thoi_gian TEXT, ghi_chu TEXT)").run();
          if (duqPosIds.length) {
            const likeLen = ky === "nam" ? 4 : 7;
            const likeVal = ky === "nam" ? String(nam) : curMonths[0];
            const placeholders = duqPosIds.map(() => "?").join(",");
            const cr = await env.DB.prepare(
              "SELECT p.don_vi_id AS duid, COUNT(DISTINCT c.pos_user_id) AS duq_cs, COUNT(*) AS luot " +
              "FROM cham_soc c JOIN nguoi_dung p ON p.id = c.pos_user_id " +
              "WHERE substr(c.thoi_gian, 1, " + likeLen + ") = ? AND c.pos_user_id IN (" + placeholders + ") GROUP BY p.don_vi_id"
            ).bind(likeVal, ...duqPosIds).all();
            const careMap = {};
            for (const r of (cr.results || [])) careMap[r.duid] = r;
            const unitDuqScale = {};
            for (const e in posByEload) {
              const p = posByEload[e];
              if (!isDuqPos(p)) continue;
              if (scopeUnitIds !== null && !scopeUnitIds.includes(p.don_vi_id)) continue;
              unitDuqScale[p.don_vi_id] = (unitDuqScale[p.don_vi_id] || 0) + 1;
            }
            const scopeDuids = scopeUnitIds === null ? Object.keys(unitDuqScale).map(Number) : scopeUnitIds.filter((id) => unitDuqScale[id]);
            const duidToName = {};
            for (const u of allUnits) duidToName[u.id] = u.ten_don_vi;
            careByUnit = scopeDuids.map((duid) => {
              const qm = unitDuqScale[duid] || 0;
              const cm = careMap[duid] || { duq_cs: 0, luot: 0 };
              const cs = Number(cm.duq_cs) || 0;
              return { don_vi_id: duid, ten: duidToName[duid] || ("Đơn vị " + duid), quy_mo_duq: qm, duq_duoc_cs: cs, ty_le: qm > 0 ? Math.round(cs / qm * 1000) / 10 : null, luot: Number(cm.luot) || 0 };
            }).sort((a, b) => (b.ty_le || 0) - (a.ty_le || 0));
          }
        } catch (e) { /* bo qua khi chua co du lieu cham soc */ }
        const trend = trendMonths.map((mk) => { const a = aggMonths([mk]); return { month: mk, subs: a.subs, revenue: Math.round(a.revenue) }; });
        const psslTrendMonths = ky === "nam" ? curMonths : months.slice(2);
        const psslTrend = psslTrendMonths.map((mk) => ({ month: mk, pssl: aggMonths([mk]).pssl.size, ke_hoach: planSum([mk], "pssl") }));
        const tyle = (actual, kh) => kh > 0 ? Math.round(actual / kh * 1000) / 10 : null;
        const by_unit = Object.keys(cur.units).map((nu) => {
          const a = cur.units[nu], b = prev.units[nu] || { subs: 0, revenue: 0 };
          const kP = unitPlan(nu, curMonths, "pssl"), kS = unitPlan(nu, curMonths, "subs"), kR = unitPlan(nu, curMonths, "revenue");
          return { name: a.name, subs: a.subs, revenue: Math.round(a.revenue), pssl: a.pssl.size,
            subs_c1: b.subs, subs_c1_pct: pct(a.subs, b.subs),
            rev_c1: Math.round(b.revenue), rev_c1_pct: pct(a.revenue, b.revenue),
            kh_pssl: kP, tyle_pssl: tyle(a.pssl.size, kP),
            kh_subs: kS, tyle_subs: tyle(a.subs, kS),
            kh_rev: Math.round(kR), tyle_rev: tyle(a.revenue, kR) };
        }).sort((x, y) => (y.revenue + y.subs) - (x.revenue + x.subs));
        const by_pos = Object.keys(cur.pos).map((e) => {
          const info = posByEload[e] || {};
          const a = cur.pos[e], b = prev.pos[e] || { subs: 0, revenue: 0 };
          return { eload: info.so_eload || e, ma_kenh: info.ma_kenh || "", ho_ten: info.ho_ten || e,
            don_vi_id: info.don_vi_id || null, don_vi_ten: info.don_vi_ten || "",
            subs: a.subs, revenue: Math.round(a.revenue),
            subs_c1: b.subs, subs_c1_pct: pct(a.subs, b.subs),
            rev_c1: Math.round(b.revenue), rev_c1_pct: pct(a.revenue, b.revenue),
            pssl: cur.pssl.has(e) ? 1 : 0 };
        }).sort((x, y) => (y.revenue + y.subs) - (x.revenue + x.subs));
        const sortVi = (a, b) => String(a).localeCompare(String(b), "vi");
        return json({
          ok: true, ky, thang: ky === "thang" ? curMonths[0] : null, nam: ky === "nam" ? nam : null,
          period_label: periodLabel, cmp1_label, cmp2_label,
          types_count: stypes.length, has_subtype_col: hasSubtypeCol,
          has_subs_src: hasSubsSrc, has_rev_src: hasRevSrc,
          kpi: {
            subs: cur.subs, subs_c1: prev.subs, subs_c1_pct: pct(cur.subs, prev.subs),
            subs_c2: c2.subs, subs_c2_pct: c2Months.length ? pct(cur.subs, c2.subs) : null,
            rev: Math.round(cur.revenue), rev_c1: Math.round(prev.revenue), rev_c1_pct: pct(cur.revenue, prev.revenue),
            rev_c2: Math.round(c2.revenue), rev_c2_pct: c2Months.length ? pct(cur.revenue, c2.revenue) : null,
            kh_subs: khSubs, tyle_subs: tyle(cur.subs, khSubs),
            kh_rev: Math.round(khRev), tyle_rev: tyle(cur.revenue, khRev),
          },
          trend,
          pssl: { count: psslCount, c1: psslPrev, c1_pct: pct(psslCount, psslPrev),
            ke_hoach: khPssl, ty_le: tyle(psslCount, khPssl), trend: psslTrend },
          duq: { quy_mo: scaleDuq, pssl: psslDuq, ty_le: tyleDuq, ty_le_c1: tyleDuqPrev,
            ty_le_c1_pct: (tyleDuq != null && tyleDuqPrev != null && tyleDuqPrev > 0) ? Math.round((tyleDuq - tyleDuqPrev) / tyleDuqPrev * 1000) / 10 : null },
          care: { by_unit: careByUnit },
          by_unit, by_pos,
          loai_tb_values: [...stSet].sort(sortVi),
        });
      }
      if (path === "/api/sales-dashboard" && method === "GET") {
        if (!hasModule(me, "salesdash")) return err("Tai khoan khong co quyen xem Dashboard ban hang", 403);
        const types = await getDataTypes(env);
        const loai = (url.searchParams.get("loai") || "").toUpperCase();
        const t = types.find((x) => x.code === loai);
        if (!t) return err("Chua chon loai du lieu ban hang", 422);
        const salesKind = t.sales_kind || "";
        // Doanh thu: can Ten don vi + So Eload + Gia goi.
        // San luong PTTB: can Ten don vi + So Eload (khong can Gia goi).
        const needPrice = salesKind !== "san_luong";
        if (!t.sales_unit_col || !t.sales_eload_col || (needPrice && !t.sales_price_col))
          return err("Loai du lieu " + t.code + " chua cau hinh du cot cho Dashboard ban hang (can: cot Ten don vi, cot So Eload" + (needPrice ? ", cot Gia goi" : "") + "). Vao Cai dat > Loai du lieu de thiet lap.", 422);
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        // Map Eload -> diem ban (chi tinh thue bao do Eload cua diem ban phat trien)
        const normE = (s) => String(s == null ? "" : s).trim().toUpperCase().replace(/\s+/g, "");
        const posRows = (await env.DB.prepare(
          "SELECT u.id, u.ho_ten, u.ma_kenh, u.so_eload, u.don_vi_id, d.ten_don_vi AS don_vi_ten " +
          "FROM nguoi_dung u LEFT JOIN don_vi d ON d.id = u.don_vi_id " +
          "WHERE u.role = 'user' AND u.so_eload IS NOT NULL AND TRIM(u.so_eload) != ''"
        ).all()).results || [];
        const posByEload = {};
        for (const pr2 of posRows) { const e = normE(pr2.so_eload); if (e && !posByEload[e]) posByEload[e] = pr2; }
        // Chuan hoa ten don vi de map vao cay don vi (lanh dao / chuyen vien)
        const normU = (s) => String(s == null ? "" : s).trim().toLowerCase()
          .normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/đ/g, "d")
          .replace(/[–—−‐‒]/g, "-").replace(/\s+/g, " ").replace(/\s*-\s*/g, "-");
        let scopeNames = null;
        const leaderScoped = isLeaderLike && me.don_vi_id;
        if (leaderScoped) {
          const urs = (await env.DB.prepare(unitSubtreeCTE() + " SELECT d.id, d.ten_don_vi FROM don_vi d WHERE d.id IN (SELECT id FROM subtree)").bind(me.don_vi_id).all()).results || [];
          scopeNames = new Set(urs.map((u) => normU(u.ten_don_vi)));
        }
        const ownOnly = !isPrivileged && !leaderScoped;
        const meEload = normE(me.so_eload || "");
        const byMonth = {}, byUnit = {}, byPos = {};
        const skippedTables = [];
        const needCols = [t.sales_unit_col, t.sales_eload_col];
        if (t.sales_price_col) needCols.push(t.sales_price_col);
        if (t.sales_kenh_col) needCols.push(t.sales_kenh_col);
        if (t.sales_qty_col) needCols.push(t.sales_qty_col);
        if (t.sales_result_col) needCols.push(t.sales_result_col);
        if (t.sales_subtype_col) needCols.push(t.sales_subtype_col);
        const fKqList = url.searchParams.getAll("ket_qua").map((s) => String(s || "").trim());
        const fStList = url.searchParams.getAll("loai_tb").map((s) => String(s || "").trim());
        const kqSet = new Set(), stSet = new Set();
        const tables = await listMonthlyTables(env, t.prefix);
        for (const tbl of tables) {
          if (!tableInRange(tbl, t.prefix, from, to)) continue;
          const cols = (await env.DB.prepare("PRAGMA table_info(" + tbl + ")").all()).results || [];
          const cn = new Set(cols.map((c) => c.name));
          if (!needCols.every((c) => cn.has(c))) { skippedTables.push(tbl); continue; }
          const rows = (await env.DB.prepare("SELECT * FROM " + tbl).all()).results || [];
          const mk = tableMonthKey(tbl);
          for (const r of rows) {
            const e = normE(r[t.sales_eload_col]);
            const pos = posByEload[e];
            if (!pos) continue;
            const kq = t.sales_result_col ? String(r[t.sales_result_col] == null ? "" : r[t.sales_result_col]).trim() : "";
            const st = t.sales_subtype_col ? String(r[t.sales_subtype_col] == null ? "" : r[t.sales_subtype_col]).trim() : "";
            const rawU = String(r[t.sales_unit_col] == null ? "" : r[t.sales_unit_col]).trim();
            const nu = normU(rawU);
            if (scopeNames && !scopeNames.has(nu)) continue;
            if (ownOnly && e !== meEload) continue;
            if (t.sales_result_col) kqSet.add(kq || "(Trống)");
            if (t.sales_subtype_col) stSet.add(st || "(Trống)");
            if (t.sales_result_col) kqSet.add(kq || "(Trống)");
            if (t.sales_subtype_col) stSet.add(st || "(Trống)");
            if (fKqList.length && !fKqList.includes(kq)) continue;
            if (fStList.length && !fStList.includes(st)) continue;
            const price = toNumber(r[t.sales_price_col]);
            let qty = t.sales_qty_col ? toNumber(r[t.sales_qty_col]) : 0;
            if (!qty || qty <= 0) qty = 1;
            const revenue = price / 1.1 * qty;
            if (!byMonth[mk]) byMonth[mk] = { subs: 0, revenue: 0 };
            byMonth[mk].subs += qty; byMonth[mk].revenue += revenue;
            if (!byUnit[nu]) byUnit[nu] = { name: rawU || "(Chưa xác định)", subs: 0, revenue: 0 };
            byUnit[nu].subs += qty; byUnit[nu].revenue += revenue;
            if (!byPos[e]) byPos[e] = { subs: 0, revenue: 0 };
            byPos[e].subs += qty; byPos[e].revenue += revenue;
          }
        }
        const by_month = Object.keys(byMonth).sort().map((m) => ({ month: m, subs: byMonth[m].subs, revenue: Math.round(byMonth[m].revenue) }));
        const by_unit = Object.values(byUnit)
          .sort((a, b) => b.revenue - a.revenue)
          .map((u) => ({ name: u.name, subs: u.subs, revenue: Math.round(u.revenue) }));
        const by_pos = Object.keys(byPos).map((e) => {
          const p = posByEload[e];
          return { eload: p.so_eload, ma_kenh: p.ma_kenh, ho_ten: p.ho_ten, don_vi_ten: p.don_vi_ten, subs: byPos[e].subs, revenue: Math.round(byPos[e].revenue) };
        }).sort((a, b) => b.revenue - a.revenue);
        const sortVi = (a, b) => String(a).localeCompare(String(b), "vi");
        return json({ ok: true, type: { code: t.code, name: t.name, kind: salesKind }, by_month, by_unit, by_pos, skipped_tables: skippedTables,
          ket_qua_values: [...kqSet].sort(sortVi), loai_tb_values: [...stSet].sort(sortVi) });
      }
      if (path === "/api/reports/detail" && method === "GET") {
        if (!hasModule(me, "reports")) return err("Tai khoan khong co quyen xem bao cao", 403);
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        const loai = (url.searchParams.get("loai") || "ALL").toUpperCase();
        const limit = Math.min(Number(url.searchParams.get("limit") || 500), 2000);
        const statusFilter = parseStatusFilter(url.searchParams.get("trang_thai"));
        const dr = await resolveScopeUnit(env, me, isLeaderLike, isPrivileged, url.searchParams.get("don_vi"));
        if (!dr.ok) return err(dr.msg, dr.code);
        const scopeUnit = dr.unit;
        const pr = await resolvePosUser(env, me, isPrivileged, isLeaderLike, url.searchParams.get("diem_ban"));
        if (!pr.ok) return err(pr.msg, pr.code);
        const posUser = pr.pos;
        const out = [];
        const skippedTables = [];
        const legacyTables = [];
        const types = await getDataTypes(env);
        const sources = types
          .filter((t) => (loai === "ALL" || t.code === loai) && t.money_col && t.time_col)
          .map((t) => buildSource(t, posUser || me, scopeUnit));
        for (const s of sources) {
          const tables = await listMonthlyTables(env, s.prefix);
          for (const t of tables) {
            if (!tableInRange(t, s.prefix, from, to)) continue;
            const runDetailTable = async (src) => {
              const sel = [
                "'" + src.code + "' AS loai",
                (src.subCol || "''") + " AS so_thue_bao",
                (src.eloadCol || "''") + " AS so_eload",
                src.money + " AS so_tien",
                (src.transCol || "''") + " AS ma_giao_dich",
                src.time + " AS thoi_gian",
                (src.statusCol || "''") + " AS trang_thai",
                (src.reasonCol || "''") + " AS nguyen_nhan_loi",
                (src.pkgCol || "''") + " AS ten_goi",
              ];
              let sql =
                "SELECT " + sel.join(", ") + ' FROM "' + t + '" WHERE substr(' + src.time + ", 1, 10) BETWEEN ? AND ?";
              const binds = [from, to];
              if (posUser) { sql += " AND " + src.own; binds.push(...src.ownBinds); }
              else if (scopeUnit != null) {
                if (scopeUnit === 0) { sql += " AND " + src.unmapped; }
                else { sql += " AND " + src.unit; binds.push(...src.unitBinds); }
              }
              else if (!isPrivileged) {
                if (isUnitScoped) { sql += " AND " + src.unit; binds.push(...src.unitBinds); }
                else { sql += " AND " + src.own; binds.push(...src.ownBinds); }
              }
              sql += " ORDER BY thoi_gian DESC LIMIT ?";
              binds.push(limit);
              return env.DB.prepare(sql).bind(...binds).all();
            };
            let res, usedLegacy = false, usedSrc = s;
            try { res = await runDetailTable(s); }
            catch (e) {
              const legacy = LEGACY_SCHEMAS[s.code];
              if (!legacy || !s.type) { skippedTables.push(t); continue; }
              try { usedSrc = buildSource({ ...s.type, ...legacy }, posUser || me, scopeUnit); res = await runDetailTable(usedSrc); usedLegacy = true; }
              catch (e2) { skippedTables.push(t); continue; }
            }
            if (usedLegacy) legacyTables.push(t);
            const hasStatus = !!usedSrc.statusCol;
            for (const r of res.results || []) {
              if (statusFilter !== "all") {
                if (hasStatus) {
                  if ((isSuccessStatus(r.trang_thai) ? "success" : "fail") !== statusFilter) continue;
                } else if (statusFilter === "fail") continue;
              }
              out.push(r);
            }
          }
        }
        out.sort((a, b) => String(b.thoi_gian || "").localeCompare(String(a.thoi_gian || "")));
        return json({ ok: true, rows: out.slice(0, limit), skipped_tables: skippedTables, legacy_tables: legacyTables, pos: posUser ? { id: posUser.id, ho_ten: posUser.ho_ten, username: posUser.username } : null });
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
      // ---- Ban do kenh ban: tat ca diem ban co toa do ----
      // Khong gioi han theo cay don vi, nhan su quan ly hay lanh dao phu
      // trach cham soc: bat ky user nao co module "channelmap" cung xem duoc
      // toan bo diem ban co toa do (chi loc hien thi o phia client).
      if (path === "/api/channel-map" && method === "GET") {
        if (!hasModule(me, "channelmap")) return err("Tai khoan khong co quyen xem ban do kenh ban", 403);
        const res = await env.DB.prepare(
          "SELECT u.id, u.ho_ten, u.ma_kenh, u.so_eload, u.so_vi, u.ten_nhan_vien, u.sdt_nhan_vien, u.ma_hrm, u.don_vi_id, d.ten_don_vi AS don_vi_ten, u.loai_kenh, u.lat, u.lng FROM nguoi_dung u LEFT JOIN don_vi d ON d.id = u.don_vi_id WHERE u.role = 'user' AND u.active = 1 AND u.lat IS NOT NULL AND u.lng IS NOT NULL ORDER BY u.ho_ten"
        ).all();
        return json({ ok: true, pos: res.results || [] });
      }
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
        const base = "SELECT u.id, u.ho_ten, u.ma_kenh, u.lat, u.lng, u.don_vi_id, d.ten_don_vi AS don_vi_ten FROM nguoi_dung u LEFT JOIN don_vi d ON d.id = u.don_vi_id WHERE u.role = 'user' AND u.active = 1 AND u.lat IS NOT NULL AND u.lng IS NOT NULL";
        let rows;
        if (isAdmin) {
          rows = (await env.DB.prepare(base).all()).results || [];
        } else {
          // Lanh dao chi thay diem ban DUOC GAN cho minh (leader_id = me.id) —
          // khong lay theo cay don vi nua; van loc ban kinh 20m o buoc sau.
          rows = (await env.DB.prepare(base + " AND u.leader_id = ?").bind(me.id).all()).results || [];
          if (!rows.length) return json({ ok: true, pos: [], reason: "no_assigned" });
        }
        // all=1: tra ve TOAN BO diem ban trong pham vi kem khoang cach (phuc vu
        // ban do cham soc) thay vi chi loc trong 20m; mac dinh giu loc 20m.
        const showAllPos = url.searchParams.get("all") === "1";
        const pos = rows
          .map((u) => ({ id: u.id, ho_ten: u.ho_ten, ma_kenh: u.ma_kenh, lat: u.lat, lng: u.lng, don_vi_ten: u.don_vi_ten, khoang_cach_m: Math.round(haversineM(lat, lng, u.lat, u.lng) * 10) / 10 }))
          .filter((u) => showAllPos || u.khoang_cach_m <= 20)
          .sort((a, b) => a.khoang_cach_m - b.khoang_cach_m)
          .slice(0, showAllPos ? 200 : 100);
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
        const pos = await env.DB.prepare("SELECT id, ho_ten, don_vi_id, lat, lng, leader_id FROM nguoi_dung WHERE id = ? AND role = 'user'").bind(posId).first();
        if (!pos || pos.lat === null || pos.lng === null) return err("Diem ban khong co toa do khai bao", 422);
        // Lanh dao chi duoc ghi nhan diem ban duoc gan cho minh (khop voi danh
        // sach nearby); admin khong bi gioi han nay.
        if (isLeader && pos.leader_id !== me.id) return err("Diem ban nay khong duoc gan cho ban cham soc", 403);
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
        if (!isPrivileged && !isLeaderLike) return err("Chi admin/subadmin va Lanh dao don vi moi xem duoc bao cao cham soc", 403);
        if (!hasModule(me, "reports")) return err("Tai khoan khong co quyen xem bao cao", 403);
        await ensureCareTables(env);
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        if (isLeaderLike && !me.don_vi_id) return json({ ok: true, tong_luot: 0, tong_diem: 0, theo_dot: [], theo_nguoi: [], theo_don_vi: [], theo_diem: [] });
        const prefix = isLeaderLike ? unitSubtreeCTE() + " " : "";
        const scopeSql = isLeaderLike ? " AND p.don_vi_id IN (SELECT id FROM subtree)" : "";
        const runQ = async (sql, extraBinds) => {
          const binds = isLeaderLike ? [me.don_vi_id, ...extraBinds] : extraBinds;
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
        if (!isPrivileged && !isLeaderLike) return err("Chi admin/subadmin va Lanh dao don vi moi xem duoc bao cao cham soc", 403);
        if (!hasModule(me, "reports")) return err("Tai khoan khong co quyen xem bao cao", 403);
        await ensureCareTables(env);
        const from = url.searchParams.get("from") || "0000-01-01";
        const to = url.searchParams.get("to") || "9999-12-31";
        const limit = Math.min(1000, Number(url.searchParams.get("limit")) || 1000);
        if (isLeaderLike && !me.don_vi_id) return json({ ok: true, records: [] });
        const base = "SELECT c.id, c.thoi_gian, dt.ten_dot, p.ho_ten AS pos_ten, d.ten_don_vi AS don_vi_ten, c.caregiver_ten, c.khoang_cach_m, c.ghi_chu FROM cham_soc c JOIN nguoi_dung p ON p.id = c.pos_user_id LEFT JOIN don_vi d ON d.id = p.don_vi_id LEFT JOIN dot_cham_soc dt ON dt.id = c.dot_id WHERE substr(c.thoi_gian, 1, 10) BETWEEN ? AND ?";
        let sql = base;
        let binds = [from, to];
        if (isLeaderLike) {
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

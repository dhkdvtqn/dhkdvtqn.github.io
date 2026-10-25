-- ============================================================================
-- VNPT - He thong quan ly chi tra hoa hong kenh diem uy quyen
-- Cau lenh SQL tao bang tren Cloudflare D1
-- Cach dung: Cloudflare Dashboard -> Storage & Databases -> D1 -> chon database
--            -> tab Console -> dan toan bo noi dung file nay -> Run.
-- ============================================================================

-- 1) Bang don vi (cau truc cay cha - con qua parent_id)
CREATE TABLE IF NOT EXISTS don_vi (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ma_don_vi TEXT UNIQUE NOT NULL,
  ten_don_vi TEXT NOT NULL,
  parent_id INTEGER,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- 2) Bang nguoi dung (admin, subadmin va diem ban)
CREATE TABLE IF NOT EXISTS nguoi_dung (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ma_kenh TEXT,
  ho_ten TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  salt TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user',        -- 'admin', 'subadmin' hoac 'user'
  so_eload TEXT,
  so_vi TEXT,
  ten_nhan_vien TEXT,                       -- Ten nhan vien quan ly (co the de trong)
  sdt_nhan_vien TEXT,                       -- So dien thoai nhan vien quan ly (co the de trong)
  don_vi_id INTEGER,                        -- Don vi truc thuoc (lien ket bang don_vi, co the de trong)
  can_import INTEGER NOT NULL DEFAULT 0,    -- 1 = duoc quyen import du lieu
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

-- 2b) Bang log dang nhap (phuc vu module Thong ke dang nhap theo thang)
CREATE TABLE IF NOT EXISTS dang_nhap_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  username TEXT,
  ho_ten TEXT,
  thoi_gian TEXT                            -- Gio Viet Nam (UTC+7), dang YYYY-MM-DD HH:mm:ss
);

-- 2c) Bang khoa thay the theo tung bang thang (admin khoa/mo khoa;
--     neu chua co dong nao: thang hien tai mac dinh MO, cac thang truoc KHOA)
CREATE TABLE IF NOT EXISTS khoa_bang (
  ten_bang TEXT PRIMARY KEY,                -- VD: HHBG_102026, BCKH_1026
  khoa INTEGER NOT NULL DEFAULT 1,          -- 1 = khoa thay the, 0 = mo
  updated_by TEXT,
  updated_at TEXT
);

-- 2d) Bang danh muc goi cuoc (module Danh muc goi cuoc)
CREATE TABLE IF NOT EXISTS goi_cuoc (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ten_goi TEXT NOT NULL,
  chu_ky TEXT NOT NULL,                     -- 1T, 3T, 6T, 12T, 18T, 24T, 36T
  gia_goi REAL NOT NULL DEFAULT 0,
  uu_dai TEXT,
  anh_key TEXT,                             -- Khoa anh tren R2 (VD: goi-cuoc/12-1729....jpg)
  noi_bat INTEGER NOT NULL DEFAULT 0,       -- 1 = admin ghim len top 5 hien thi
  noi_bat_at TEXT,                          -- Thoi diem ghim (de sap xep top 5)
  created_by TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT,
  UNIQUE(ten_goi, chu_ky)
);

-- 3) Tai khoan admin ban dau
--    Ten dang nhap: admin  |  Mat khau: Vnpt@2026
--    HAY DANG NHAP VA DOI MAT KHAU NGAY SAU KHI CAI DAT XONG!
INSERT OR IGNORE INTO nguoi_dung
  (ma_kenh, ho_ten, username, password_hash, salt, role, can_import)
VALUES
  ('ADMIN', 'Quan tri vien', 'admin',
   'dda8cd32c5dcab690f832bfceddf4d15eec944a2b5ade7349694a281b212a3ae',
   'vnpt-seed-2026', 'admin', 1);

-- ============================================================================
-- NANG CAP CHO CSDL DA TAO TU TRUOC (chi chay 1 lan, neu bao "duplicate
-- column name" thi cot da co san - bo qua):
--
-- ALTER TABLE nguoi_dung ADD COLUMN ten_nhan_vien TEXT;
-- ALTER TABLE nguoi_dung ADD COLUMN sdt_nhan_vien TEXT;
-- ALTER TABLE nguoi_dung ADD COLUMN don_vi_id INTEGER;
--
-- (Thuc te Worker se tu dong bo sung 2 cot nay khi chay, va tu tao bang
--  dang_nhap_log o lan dang nhap dau tien, nen buoc nay khong bat buoc.)
-- ============================================================================

-- ============================================================================
-- LUU Y ve bang du lieu import theo thang:
-- Worker se TU DONG tao bang moi khi import, dung dinh dang ten:
--   HHBG_MMYYYY  (du lieu chi tra hoa hong ban goi cua 1 thang)
--   BCKH_MMYY    (du lieu chi tra tien BCKH cua 1 thang)
-- Vi du cau truc cua 2 loai bang (chi de tham khao, khong can chay tay):
--
-- CREATE TABLE HHBG_102026 (
--   id INTEGER PRIMARY KEY AUTOINCREMENT,
--   ten_eload TEXT, so_eload TEXT, so_vi TEXT, so_thue_bao TEXT,
--   loai_thue_bao TEXT, chu_ky_chi_tra TEXT, ten_goi TEXT, gia_goi REAL,
--   thoi_gian_giao_dich TEXT, trans_id TEXT, kenh_thuc_hien TEXT,
--   thu_lao REAL, ma_giao_dich TEXT, thoi_gian_chi_tra TEXT,
--   trang_thai TEXT, nguyen_nhan_loi TEXT,
--   imported_by TEXT, imported_at TEXT DEFAULT CURRENT_TIMESTAMP
-- );
--
-- CREATE TABLE BCKH_1026 (
--   id INTEGER PRIMARY KEY AUTOINCREMENT,
--   so_eload TEXT, ten_eload TEXT, so_thue_bao TEXT,
--   thoi_gian_kich_hoat TEXT, hoa_hong_bckh REAL, ma_giao_dich TEXT,
--   thoi_gian_chi_tra TEXT, trang_thai TEXT, nguyen_nhan_loi TEXT,
--   imported_by TEXT, imported_at TEXT DEFAULT CURRENT_TIMESTAMP
-- );
-- ============================================================================

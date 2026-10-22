# Hệ thống quản lý chi trả hoa hồng — Kênh điểm ủy quyền VNPT

Trang thông tin cơ chế chính sách dành cho kênh điểm ủy quyền của VNPT (áp dụng từ
01/10/2026) kèm hệ thống quản lý đăng nhập cho admin và các điểm bán.

Xem trực tiếp tại: https://dhkdvtqn.github.io/

## Nội dung

- **Trang công khai**: infographic 5 mục chính sách + công cụ "Ước tính thu nhập
  của điểm bán" (3 phần: chi phí đầu tư, dự toán chi trả, giá vốn SIM).
- **Hệ thống quản lý** (nút Đăng nhập ở góc trên phải):
  - Admin: Quản lý đơn vị (cây cha–con), Quản lý người dùng, Quản lý dữ liệu
    đầu vào (import Excel theo tháng vào bảng `HHBG_MMYYYY` / `BCKH_MMYY`),
    Cấu hình kết nối Cloudflare D1 (kèm hướng dẫn cài đặt từng bước).
  - Mọi người dùng: Báo cáo thống kê (tổng hợp + chi tiết), Cài đặt tài khoản
    (đổi mật khẩu, số Eload, số Ví VNPT Money).

## Kiến trúc

- `index.html` — toàn bộ giao diện web (đăng trên GitHub Pages).
- `worker.js` — mã nguồn Cloudflare Worker làm API trung gian, kết nối CSDL
  Cloudflare D1 (binding `DB`). Cần deploy lên tài khoản Cloudflare của đơn vị.
- `schema.sql` — câu lệnh SQL tạo bảng `don_vi`, `nguoi_dung` và tài khoản
  admin ban đầu (`admin` / `Vnpt@2026`) trên D1.

Hướng dẫn cài đặt chi tiết từng bước có ngay trong module **Cấu hình kết nối
D1** trên website sau khi đăng nhập (hoặc khi mở cửa sổ đăng nhập lần đầu).

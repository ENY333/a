# CLOUD 2FA Authenticator

Web TOTP authenticator chạy thuần frontend, phù hợp deploy GitHub Pages hoặc Vercel.

## Tính năng
- Thêm Secret Key TOTP
- Dán `otpauth://totp/...`
- Tự tạo OTP 6/8 số
- SHA-1 / SHA-256 / SHA-512
- Chu kỳ 15/30/60 giây
- Lưu nhiều key bằng `localStorage`
- Đặt tên / đổi tên / xóa key
- Copy OTP
- Dark / Light mode
- Không cần backend
- Secret không được gửi lên server

## Lưu ý bảo mật
Secret được lưu trong localStorage của trình duyệt dưới dạng plaintext. Đây là bản local-first tiện dụng, không phải vault bảo mật chuyên dụng. Không dùng trên máy tính dùng chung hoặc máy không đáng tin cậy.

## Deploy GitHub Pages
1. Tạo repository.
2. Upload `index.html`, `style.css`, `app.js`, `README.md`.
3. Vào Settings → Pages.
4. Chọn Deploy from branch → `main` → `/root`.
5. Save.

Không cần Node.js, npm hoặc backend.

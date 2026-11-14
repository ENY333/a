# CLOUD 2FA Authenticator V2

## Nhập nhiều dạng

1. **Secret Key**
   - `JBSWY3DPEHPK3PXP`
   - `JBSW Y3DP EHPK 3PXP`
   - `JBSW-Y3DP-EHPK-3PXP`
   - Có thể có dấu `=`

2. **otpauth URI**
   - `otpauth://totp/...?...`
   - Tự lấy secret, issuer, digits, algorithm, period.

3. **Dán dữ liệu**
   Có thể dán cả đoạn hướng dẫn như:
   Email: example@gmail.com
   Key: JBSW Y3DP EHPK 3PXP
   Type: Time based
   Digits: 6
   Algorithm: SHA-1
   Period: 30

## Lưu trữ
Key được lưu local trên trình duyệt bằng localStorage. Không có backend/API gửi secret lên Vercel.

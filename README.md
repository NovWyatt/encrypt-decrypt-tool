# Encrypt/Decrypt Tool

Công cụ mã hóa và giải mã file văn bản bằng **AES** và **RSA**, từ cơ bản đến nâng cao. Mọi thao tác chạy ngay trong trình duyệt trên máy bạn: không có máy chủ, không gửi dữ liệu đi đâu.

> Dự án đang được xây dựng. README sẽ được cập nhật đầy đủ khi giao diện hoàn thiện.

## Chạy thử

```bash
npm install
npm run dev
```

## Kiểm thử

```bash
npm test
```

Bộ test đối chiếu với các vector chuẩn (NIST SP 800-38A, RFC 7914, RFC 6070) và với OpenSSL (qua `node:crypto` và lệnh `openssl` nếu máy có cài).

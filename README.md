# SoftHSM v2 Manager

跨平台 GUI 應用，用於管理 SoftHSMv2 HSM 的加密 Key。

## 功能

- **Generate RSA Key** — RSA-2048 / RSA-4096
- **Generate EC Key** — P-256 / P-384 / P-521
- **Import PKCS#8** — 導入私鑰
- **Export Public Key** — PEM 格式導出
- **Delete Object** — 刪除 Key
- **Multi-Source HSM** — Local SoftHSM / SSH Remote

## 支援平台

- Linux amd64 / arm64
- Windows amd64 (.exe)

Build 全自動通過 GitHub Actions，無需本地安裝 Go。

## 架構

```
softhsm-gui (Fyne Go GUI)
├── local backend   — libsofthsm2.so via go-pkcs11
└── ssh backend     — ssh user@host softhsm2-util
```

## 安裝

下載 Release artifact：
- Linux: `softhsm-gui-linux-amd64`
- Windows: `softhsm-gui-windows-amd64.exe`

## 開發

```bash
# 依賴
go mod download

# 運行（需要 X11/顯示）
go run .

# 交叉編譯
GOOS=linux GOARCH=amd64 CGO_ENABLED=1 go build -o softhsm-gui .

# 交叉編譯 Windows
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 go build -o softhsm-gui.exe .
```

## 依賴

- [Fyne](https://fyne.io/) v2.4.3 — GUI framework
- [miekg/pkcs11](https://github.com/miekg/pkcs11) — PKCS#11 binding

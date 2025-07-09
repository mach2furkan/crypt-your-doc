# 🔐 AES File Encryptor (PRIVATE)

> 🚨 **UYARI:** Bu yazılım yalnızca geliştirici **Furkan Aşkın** tarafından kendi cihazında kullanılmak üzere geliştirilmiştir.  
> Her türlü dağıtım, çoğaltma, paylaşım veya üçüncü kişiye iletim **kesinlikle yasaktır**.

<p align="center">
  <img src="https://img.shields.io/badge/Durum-Yalnızca%20Kişisel%20Kullanım-red?style=for-the-badge&logo=go" />
  <img src="https://img.shields.io/badge/Geliştirici-Furkan%20Aşkın-blue?style=for-the-badge" />
</p>

---

## 🎬 Tanıtım

<p align="center">
  <img src="docs/demo.gif" width="600" alt="AES Şifreleme Demo" />
  <br />
  <i>✔️ Dosya seçimi ➜ 🔐 Şifreleme ➜ 📦 ZIP olarak indirme ➜ 🔓 Çözme</i>
</p>

---

## 📖 Proje Hakkında

Bu uygulama, **AES-256 şifreleme algoritması** kullanarak dosyalarınızı yüksek güvenlikle korur.  
Tarayıcı üzerinden çalışan modern bir arayüzle, dosyaları kolayca **şifreleyebilir veya çözebilirsiniz**.  

**Go (Golang)** ile geliştirilen sistem herhangi bir sunucu veya dış servis kullanmaz. Tüm işlemler lokal olarak yapılır.

---

## ⚙️ Temel Özellikler

| Özellik | Açıklama |
|--------|----------|
| 🔐 **AES-256-CBC** | Endüstri standardı blok şifreleme |
| 🧠 PBKDF2 + SHA-256 | Parola türetme ile ekstra güvenlik |
| 📂 Çoklu Dosya Desteği | Birden fazla dosya şifrelenebilir |
| 📦 ZIP Arşivi | Şifrelenen tüm dosyalar tek bir ZIP ile indirilir |
| 👤 Giriş Paneli | `admin / 1234` kullanıcı doğrulaması |
| 📡 Sunucusuz | Tüm veriler **lokal olarak** işlenir |
| 🖼️ UI Animasyonları | Parola göster/gizle, yükleme spinner, dosya listesi renkli uyarı |
| 🚫 Veri Saklama Yok | Ne parola ne dosya diskte tutulur |

---

## 🌐 Web Arayüzü

<p align="center">
  <img src="docs/ui-preview.png" width="700" alt="Web UI Preview" />
</p>

- ✔️ Mobil uyumlu
- 🎨 Gradient arkaplanlar
- 🧩 Dinamik dosya uyarıları
- 👁️ Parola göster/gizle butonu
- 🌀 Yükleme sırasında animasyonlu spinner

---

## 🧪 Kurulum ve Kullanım

### 💻 Gereksinimler

- [Go](https://go.dev/dl/) 1.20+ (yüklü olmalı)
- Modern bir web tarayıcı (Chrome, Firefox, Safari)

### 🚀 Uygulamayı Başlat

```bash
git clone https://github.com/mach2furkan/[repo-adi]
go run main.go

# crypt-your-doc
# 🔐 AES File Encryptor (PRIVATE)

🚫 **UYARI:**  
Bu yazılım yalnızca geliştirici (Furkan Aşkın) tarafından **kişisel cihazda** kullanılmak üzere geliştirilmiştir.  
**Paylaşım, dağıtım, çoğaltma veya herhangi bir üçüncü kişiye iletim kesinlikle yasaktır.**

---

## 📖 Proje Hakkında

Bu proje, kullanıcıların dosyalarını **yüksek güvenlikli AES-256 şifreleme** algoritmasıyla şifrelemesini ve gerektiğinde çözmesini sağlayan web tabanlı bir uygulamadır.  
**Go (Golang)** programlama dili ile geliştirilen bu uygulama, herhangi bir dış veritabanı veya harici bağımlılık gerektirmeden lokal olarak çalışır.

Amaç, kolay kullanımlı ama güçlü şifreleme destekli bir çözüm sunmaktır. Özellikle kişisel dosya güvenliği için idealdir.

---

## 📌 Özellikler

- 🔐 **AES-256-CBC** algoritması ile şifreleme ve çözme desteği
- 📦 Çoklu dosya yükleme imkânı (her biri max 10MB)
- 📁 Yüklenen dosyalar işlendikten sonra **otomatik ZIP arşiv** halinde indirilir
- 🌐 Şık ve modern **web arayüzü**
- 👤 Giriş paneli: kullanıcı adı & parola korumalı (admin / 1234)
- 🧠 Şifreleme işlemlerinde PBKDF2 + SHA-256 kullanımı (parola türetimi)
- 🚫 Herhangi bir dosya veya parola sunucuya **kaydedilmez**
- 🔍 Basit hata log kaydı (JSON formatında)
- 🌱 Tüm kod Go standardına uygundur, bağımsız ve taşınabilirdir

---

## 🧪 Nasıl Kullanılır?

### 🖥️ Gereksinimler

- Go 1.20+ sürümü
- Modern bir web tarayıcı (Chrome, Firefox, Safari vs.)

### 🚀 Başlatmak için:

```bash
git clone https://github.com/mach2furkan/[repo-adı]
cd [repo-adı]
go run main.go

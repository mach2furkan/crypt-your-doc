package main

import (
	"archive/zip"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
	"html/template"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	saltSize      = 16
	ivSize        = aes.BlockSize
	keySize       = 32
	iterations    = 100000
	maxUploadSize = 10 << 20 // 10 MB per file

	adminUser     = "admin"
	adminPassword = "1234"

	sessionCookieName = "session_token"
	logFile           = "logs.json"
)

type LogEntry struct {
	Time    string `json:"time"`
	Event   string `json:"event"`
	Message string `json:"message"`
}

func LogError(event string, err error) {
	entry := LogEntry{
		Time:    time.Now().Format(time.RFC3339),
		Event:   event,
		Message: err.Error(),
	}
	file, _ := openLogFile()
	defer file.Close()
	jsonData, _ := json.Marshal(entry)
	file.Write(jsonData)
	file.Write([]byte("\n"))
}

func openLogFile() (*os.File, error) {
	return os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
}

func deriveKey(password string, salt []byte) []byte {
	return pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	return append(data, bytes.Repeat([]byte{byte(pad)}, pad)...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("geçersiz padding")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize {
		return nil, fmt.Errorf("geçersiz pad değeri")
	}
	return data[:len(data)-pad], nil
}

func encryptData(data []byte, password string) ([]byte, error) {
	salt := make([]byte, saltSize)
	iv := make([]byte, ivSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	padded := pkcs7Pad(data, block.BlockSize())
	cipherText := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, padded)
	final := append(salt, iv...)
	final = append(final, cipherText...)
	return final, nil
}

func decryptData(data []byte, password string) ([]byte, error) {
	if len(data) < saltSize+ivSize {
		return nil, fmt.Errorf("veri çok kısa")
	}
	salt := data[:saltSize]
	iv := data[saltSize : saltSize+ivSize]
	cipherText := data[saltSize+ivSize:]
	key := deriveKey(password, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(cipherText)%block.BlockSize() != 0 {
		return nil, fmt.Errorf("şifreli veri blok boyutuyla uyumsuz")
	}
	plainPadded := make([]byte, len(cipherText))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plainPadded, cipherText)
	plain, err := pkcs7Unpad(plainPadded, block.BlockSize())
	if err != nil {
		return nil, err
	}
	return plain, nil
}

// --- Templates ---

var loginTpl = template.Must(template.New("login").Parse(`
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8" />
<title>Giriş - AES Dosya Şifreleme</title>
<style>
  body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg,#667eea,#764ba2);
    color: white;
    margin: 0; padding: 0;
    height: 100vh;
    display: flex;
    justify-content: center; align-items: center;
  }
  .login-box {
    background: rgba(0,0,0,0.5);
    padding: 40px;
    border-radius: 12px;
    box-shadow: 0 0 20px rgba(0,0,0,0.3);
    width: 320px;
  }
  h2 {
    text-align: center;
    margin-bottom: 24px;
  }
  input[type=text], input[type=password] {
    width: 100%;
    padding: 12px;
    margin: 8px 0 16px;
    border: none;
    border-radius: 8px;
  }
  button {
    width: 100%;
    background-color: #6c63ff;
    border: none;
    padding: 14px;
    border-radius: 8px;
    color: white;
    font-weight: bold;
    cursor: pointer;
    font-size: 16px;
  }
  button:hover {
    background-color: #574b90;
  }
  .error {
    background: #ff4d4d;
    padding: 8px;
    border-radius: 6px;
    margin-bottom: 12px;
    text-align: center;
  }
</style>
</head>
<body>
  <div class="login-box">
    <h2>Giriş Yap</h2>
{{if .Error}}
  <div class="error">{{.Error}}</div>
{{end}}
<form method="POST" action="/login">
  <input 
    type="text" 
    name="username" 
    placeholder="Kullanıcı Adı" 
    required 
    autofocus 
    autocomplete="username"
    class="input-field"
  >
  <div class="password-wrapper">
    <input 
      type="password" 
      id="password" 
      name="password" 
      placeholder="Parola" 
      required 
      autocomplete="current-password"
      class="input-field password-input"
    >
    <span id="togglePass" class="toggle-pass">👁️</span>
  </div>
  <button type="submit" class="btn-submit">Giriş</button>
</form>

<style>
  h2 {
    text-align: center;
    margin-bottom: 24px;
    font-weight: 700;
    font-size: 26px;
  }
  .error {
    background: #ff4d4d;
    padding: 10px 12px;
    border-radius: 8px;
    margin-bottom: 16px;
    text-align: center;
    font-weight: 600;
    color: white;
  }
  .input-field {
    width: 100%;
    padding: 14px 16px;
    margin: 8px 0 20px;
    border: none;
    border-radius: 10px;
    font-size: 16px;
    box-sizing: border-box;
  }
  .password-wrapper {
    position: relative;
  }
  .password-input {
    padding-right: 44px; /* Toggle için boşluk */
  }
  .toggle-pass {
    position: absolute;
    right: 14px;
    top: 50%;
    transform: translateY(-50%);
    cursor: pointer;
    user-select: none;
    color: #666;
    font-size: 20px;
    transition: color 0.3s ease;
  }
  .toggle-pass:hover {
    color: #333;
  }
  .btn-submit {
    width: 100%;
    background-color: #6c63ff;
    border: none;
    padding: 16px 0;
    border-radius: 10px;
    color: white;
    font-weight: 700;
    cursor: pointer;
    font-size: 18px;
    transition: background-color 0.3s ease;
  }
  .btn-submit:hover {
    background-color: #574b90;
  }
</style>

<script>
  const passInput = document.getElementById('password');
  const toggle = document.getElementById('togglePass');
  toggle.onclick = function() {
    if (passInput.type === 'password') {
      passInput.type = 'text';
      toggle.textContent = '🙈';
    } else {
      passInput.type = 'password';
      toggle.textContent = '👁️';
    }
  };
</script>
</body>
</html>
`))

var panelTpl = template.Must(template.New("panel").Parse(`
<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="UTF-8" />
<title>Şifreleme Paneli</title>
<style>
  /* Genel sayfa ayarları */
  body {
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);
    color: #222;
    margin: 0; padding: 0;
    max-width: 720px;
    margin-left: auto;
    margin-right: auto;
    padding-top: 40px;
  }

  h1 {
    text-align: center;
    margin-bottom: 30px;
    color: #004d99;
    text-shadow: 1px 1px 3px rgba(0,0,0,0.1);
  }

  form {
    background: #f0faff;
    padding: 25px 30px 35px 30px;
    border-radius: 14px;
    box-shadow: 0 8px 20px rgba(0,123,255,0.2);
    transition: box-shadow 0.3s ease;
  }
  form:hover {
    box-shadow: 0 12px 30px rgba(0,123,255,0.4);
  }

  label {
    display: block;
    margin-top: 18px;
    font-weight: 600;
    color: #0066cc;
    font-size: 16px;
  }

  input[type=file], input[type=password], select {
    margin-top: 8px;
    width: 100%;
    padding: 14px 16px;
    border-radius: 10px;
    border: 1.8px solid #a0d2ff;
    font-size: 16px;
    font-weight: 500;
    transition: border-color 0.25s ease;
  }
  input[type=file]:hover, input[type=password]:hover, select:hover {
    border-color: #3399ff;
  }
  input[type=file] {
    cursor: pointer;
  }

  button {
    margin-top: 30px;
    width: 100%;
    background-color: #007bff;
    border: none;
    color: white;
    font-weight: 700;
    padding: 18px 0;
    font-size: 20px;
    border-radius: 12px;
    cursor: pointer;
    box-shadow: 0 4px 14px rgba(0,123,255,0.6);
    transition: background-color 0.3s ease;
  }
  button:hover {
    background-color: #0056b3;
  }

  .message {
    margin-top: 28px;
    padding: 16px;
    border-radius: 12px;
    font-weight: 700;
    text-align: center;
    font-size: 17px;
    user-select: none;
  }
  .message.success {
    background-color: #d4edda;
    color: #155724;
    border: 1.5px solid #c3e6cb;
  }
  .message.error {
    background-color: #f8d7da;
    color: #721c24;
    border: 1.5px solid #f5c6cb;
  }

  .logout {
    text-align: right;
    margin-bottom: 25px;
  }
  .logout a {
    color: #004d99;
    text-decoration: none;
    font-weight: 700;
    font-size: 16px;
    border-bottom: 2px solid transparent;
    transition: border-color 0.25s ease;
  }
  .logout a:hover {
    border-color: #004d99;
  }

  #fileList {
    margin-top: 12px;
    font-size: 15px;
    color: #003366;
    min-height: 30px;
  }

  /* Parola görünürlük ikonu */
  #togglePass {
    position: absolute;
    right: 14px;
    top: 50%;
    transform: translateY(-50%);
    cursor: pointer;
    user-select: none;
    font-size: 22px;
    color: #3399ff;
    transition: color 0.25s ease;
  }
  #togglePass:hover {
    color: #0056b3;
  }
  .password-wrapper {
    position: relative;
    margin-top: 8px;
  }

  /* Spinner */
  #spinner {
    display: none;
    margin: 30px auto 0;
    text-align: center;
    font-weight: 600;
    color: #007bff;
  }
  .lds-ring {
    display: inline-block;
    position: relative;
    width: 56px;
    height: 56px;
  }
  .lds-ring div {
    box-sizing: border-box;
    display: block;
    position: absolute;
    width: 44px;
    height: 44px;
    margin: 6px;
    border: 5px solid #007bff;
    border-radius: 50%;
    animation: lds-ring 1.2s cubic-bezier(0.5, 0, 0.5, 1) infinite;
    border-color: #007bff transparent transparent transparent;
  }
  .lds-ring div:nth-child(1) { animation-delay: -0.45s; }
  .lds-ring div:nth-child(2) { animation-delay: -0.3s; }
  .lds-ring div:nth-child(3) { animation-delay: -0.15s; }
  @keyframes lds-ring {
    0%   { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }
</style>
</head>
<body>
  <div class="logout">
    <a href="/logout" title="Çıkış Yap">🚪 Çıkış Yap</a>
  </div>

  <h1>Dosya Şifreleme / Çözme Paneli</h1>

  <form id="encForm" action="/process" method="post" enctype="multipart/form-data" onsubmit="return startProcessing()">
    <label for="modeSelect">İşlem Seçin:</label>
    <select id="modeSelect" name="mode" required>
      <option value="encrypt">Şifrele</option>
      <option value="decrypt">Çöz</option>
    </select>

    <label for="fileInput">Dosya Seçin (max 10MB her dosya):</label>
    <input type="file" id="fileInput" name="files" multiple required accept="*/*">
    <div id="fileList">Henüz dosya seçilmedi.</div>

    <label for="passwordInput">Parola Girin:</label>
    <div class="password-wrapper">
      <input type="password" id="passwordInput" name="password" required autocomplete="off" placeholder="Parolanızı girin...">
      <span id="togglePass" title="Parolayı Göster/Gizle">👁️</span>
    </div>

    <button type="submit">İşlemi Başlat</button>
  </form>

  <div id="spinner" aria-live="polite" aria-busy="true" role="alert" aria-label="Dosyalar işleniyor">
    <div class="lds-ring"><div></div><div></div><div></div><div></div></div>
    <p>Lütfen bekleyin, dosyalar işleniyor...</p>
  </div>

  {{if .Message}}
  <div class="message {{if .Error}}error{{else}}success{{end}}">
    {{.Message}}
  </div>
  {{end}}

<script>
  // Parola görünürlüğü toggle
  const passwordInput = document.getElementById('passwordInput');
  const togglePass = document.getElementById('togglePass');
  togglePass.onclick = function() {
    if(passwordInput.type === 'password') {
      passwordInput.type = 'text';
      togglePass.textContent = '🙈';
    } else {
      passwordInput.type = 'password';
      togglePass.textContent = '👁️';
    }
  };

  // Dosya seçimi ve listeleme
  const fileInput = document.getElementById('fileInput');
  const fileList = document.getElementById('fileList');
  const MAX_UPLOAD = {{.MaxUploadBytes}};

  fileInput.addEventListener('change', () => {
    fileList.textContent = '';
    let totalSize = 0;
    const files = fileInput.files;
    if(files.length === 0) {
      fileList.textContent = 'Dosya seçilmedi.';
      fileList.style.color = '#555';
      return;
    }
    for(let i=0; i<files.length; i++) {
      const f = files[i];
      totalSize += f.size;
      const sizeMB = (f.size / (1024*1024)).toFixed(2);
      let warn = f.size > MAX_UPLOAD ? ' ⚠️ Dosya boyutu çok büyük!' : '';
      const item = document.createElement('div');
      item.textContent = f.name + ' (' + sizeMB + ' MB)' + warn;
      item.style.color = f.size > MAX_UPLOAD ? '#d9534f' : '#222';
      fileList.appendChild(item);
    }
    if(totalSize > (MAX_UPLOAD * files.length)) {
      fileList.style.color = '#d9534f';
      fileList.textContent += ' | Toplam dosya boyutu limitini aşıyor!';
    } else {
      fileList.style.color = '#333';
    }
  });

  // Spinner göster / gizle ve form validasyonu
  function startProcessing() {
    const files = fileInput.files;
    for(let i=0; i<files.length; i++) {
      if(files[i].size > MAX_UPLOAD) {
        alert(files[i].name + ' dosyası çok büyük! (Maksimum 10MB)');
        return false;
      }
    }
    document.getElementById('spinner').style.display = 'block';
    return true;
  }
</script>

</body>
</html>
`))

// Basit session map (production için değil)
var sessions = map[string]time.Time{}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}

func authMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookieName)
		if err != nil || cookie == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		expireTime, ok := sessions[cookie.Value]
		if !ok || time.Now().After(expireTime) {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

func loginGetHandler(w http.ResponseWriter, r *http.Request) {
	loginTpl.Execute(w, nil)
}

func loginPostHandler(w http.ResponseWriter, r *http.Request) {
	username := r.FormValue("username")
	password := r.FormValue("password")

	if username != adminUser || password != adminPassword {
		loginTpl.Execute(w, struct{ Error string }{"Kullanıcı adı veya parola yanlış!"})
		return
	}

	token := randomToken()
	sessions[token] = time.Now().Add(30 * time.Minute)

	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		Expires:  sessions[token],
		HttpOnly: true,
	})

	http.Redirect(w, r, "/panel", http.StatusSeeOther)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		delete(sessions, cookie.Value)
		http.SetCookie(w, &http.Cookie{
			Name:    sessionCookieName,
			Value:   "",
			Path:    "/",
			Expires: time.Unix(0, 0),
		})
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func panelHandler(w http.ResponseWriter, r *http.Request) {
	data := struct {
		MaxUploadBytes int64
	}{
		MaxUploadBytes: maxUploadSize,
	}
	panelTpl.Execute(w, data)
}

func processHandler(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(maxUploadSize * 20) // max 20 dosya (max 200MB toplam)
	if err != nil {
		http.Error(w, "Dosya çok büyük veya gönderilemedi", http.StatusBadRequest)
		return
	}
	mode := r.FormValue("mode")
	password := r.FormValue("password")
	if len(password) < 4 {
		http.Error(w, "Parola en az 4 karakter olmalı", http.StatusBadRequest)
		return
	}

	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		http.Error(w, "Dosya seçilmedi", http.StatusBadRequest)
		return
	}

	// Zip dosya hazırlığı
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	for _, fheader := range files {
		if fheader.Size > maxUploadSize {
			http.Error(w, fheader.Filename+" dosyası çok büyük", http.StatusBadRequest)
			zipWriter.Close()
			return
		}
		file, err := fheader.Open()
		if err != nil {
			http.Error(w, "Dosya açılamadı: "+fheader.Filename, http.StatusInternalServerError)
			zipWriter.Close()
			return
		}
		data, err := io.ReadAll(file)
		file.Close()
		if err != nil {
			http.Error(w, "Dosya okunamadı: "+fheader.Filename, http.StatusInternalServerError)
			zipWriter.Close()
			return
		}

		var processed []byte
		switch mode {
		case "encrypt":
			processed, err = encryptData(data, password)
		case "decrypt":
			processed, err = decryptData(data, password)
		default:
			http.Error(w, "Geçersiz işlem", http.StatusBadRequest)
			zipWriter.Close()
			return
		}
		if err != nil {
			http.Error(w, "İşlem hatası: "+err.Error(), http.StatusInternalServerError)
			zipWriter.Close()
			return
		}

		outname := fheader.Filename
		if mode == "encrypt" {
			outname += ".enc"
		} else {
			if strings.HasSuffix(outname, ".enc") {
				outname = strings.TrimSuffix(outname, ".enc") + ".dec"
			} else {
				outname += ".dec"
			}
		}

		fw, err := zipWriter.Create(outname)
		if err != nil {
			http.Error(w, "Zip dosyası oluşturulamadı", http.StatusInternalServerError)
			zipWriter.Close()
			return
		}
		_, err = fw.Write(processed)
		if err != nil {
			http.Error(w, "Zip dosyasına yazılamadı", http.StatusInternalServerError)
			zipWriter.Close()
			return
		}
	}

	zipWriter.Close()

	zipFilename := fmt.Sprintf("output_%d.zip", time.Now().Unix())

	w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(zipFilename))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Write(buf.Bytes())
}

func main() {
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			loginGetHandler(w, r)
		} else if r.Method == http.MethodPost {
			loginPostHandler(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/panel", authMiddleware(panelHandler))
	http.HandleFunc("/process", authMiddleware(processHandler))

	fmt.Println("Sunucu 8080 portunda başlatıldı...")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		fmt.Println("Sunucu başlatılamadı:", err)
	}
}

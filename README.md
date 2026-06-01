# PhishCatch 🎣

A Flask-based phishing URL analyzer that scores suspicious URLs across 7 security vectors and displays a real-time risk dashboard.

> Built as a university portfolio project by [Muskan](https://github.com/yadavmuskan501-cloud)

---

## 🚀 Live Demo

| Version | URL |
|---|---|
| Local | [http://localhost:5000](http://localhost:5000) |
| Production | Coming soon — deploy to Render for a live URL |

---

## 📸 Preview

![PhishCatch UI](static/preview.png)

---

## 🔍 What It Detects

| Check | What It Looks For | Risk Weight |
|---|---|---|
| HTTPS | Plain HTTP with no TLS — trivially spoofed | High |
| Domain Age | Domains registered < 6 months ago | High |
| Suspicious TLD | `.tk` `.ml` `.ga` `.xyz` and other abuse-heavy TLDs | Medium |
| URL Length | URLs longer than 75 characters | Medium |
| Domain Entropy | High randomness = algorithmically generated domain | Medium |
| Brand Spoofing | Brand keywords (paypal, google, bank) in wrong domain | High |
| Redirect Chain | 3+ hops = likely cloaking or traffic distribution | Medium |

---

## 🧠 Scoring Logic

Each check returns a pass or fail. The final score is calculated as:

```python
score = round((passed_checks / total_checks) * 100)

risk = "Low"    if score >= 80
risk = "Medium" if score >= 50
risk = "High"   if score <  50
```

| Checks Passed | Score | Risk Level |
|---|---|---|
| 7 / 7 | 100 | 🟢 Low |
| 6 / 7 | 85  | 🟢 Low |
| 5 / 7 | 71  | 🟡 Medium |
| 4 / 7 | 57  | 🟡 Medium |
| 3 / 7 | 42  | 🔴 High |
| 2 / 7 | 28  | 🔴 High |
| 1 / 7 | 14  | 🔴 High |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.10+ / Flask |
| URL Analysis | tldextract, dnspython |
| WHOIS Lookup | python-whois |
| HTTP Checks | requests, pyOpenSSL |
| Frontend | HTML / CSS / Vanilla JS |
| Font | JetBrains Mono, Space Grotesk |

---

## 📁 Project Structure

```
phishcatch/
├── app.py                  ← Flask app + routes
├── analyzer/
│   ├── __init__.py
│   ├── url_checks.py       ← 6 core checks + scoring
│   └── whois_check.py      ← Domain age via WHOIS
├── templates/
│   └── index.html          ← Dark terminal UI
├── static/
│   └── style.css
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/yadavmuskan501-cloud/phishcatch.git
cd phishcatch
```

### 2. Create and activate virtual environment

```bash
# Mac / Linux
python3 -m venv venv
source venv/bin/activate

# Windows PowerShell
python -m venv venv
venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
python app.py
```

### 5. Open in browser

```
http://localhost:5000
```

---

## 🧪 Test URLs

Try these to see different risk levels:

| URL | Expected Result |
|---|---|
| `http://paypal-login.tk/verify` | 🔴 High Risk |
| `http://google-secure-login.xyz/reset` | 🔴 High Risk |
| `https://github.com` | 🟢 Low Risk |
| `https://amazon.com` | 🟢 Low Risk |

---

## 🗺️ Roadmap

- [x] HTTPS check
- [x] Domain age via WHOIS
- [x] Suspicious TLD detection
- [x] URL length check
- [x] Domain entropy analysis
- [x] Brand spoofing detection
- [x] Redirect chain analysis
- [ ] SSL certificate validity check
- [ ] VirusTotal API integration
- [ ] Scan history with SQLite
- [ ] Export report as PDF
- [ ] Deploy to Render

---

## 📝 Git History

```
feat: frontend — dark terminal UI with score ring
feat: flask routes — /analyze POST endpoint
feat: whois domain age check
feat: url analyzer — 6 checks
deps: add flask, whois, dns, ssl, tldextract
init: project scaffold with folder structure
```

---

## 👤 Author

**Muskan**
- GitHub: [@yadavmuskan501-cloud](https://github.com/yadavmuskan501-cloud)

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).
```

---

## Save and push

```powershell
git add README.md
git commit -m "docs: add localhost URL to live demo section"
git push
```

👍

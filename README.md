# 🛡️ Phishing Detection Tool (InfoSec Project)

A Python-based **Phishing Detection System** developed as part of an Information Security project. This tool helps analyze suspicious URLs and generate detailed phishing reports in multiple formats. It's ideal for InfoSec students, developers, and cyber-awareness enthusiasts.

---

## 📌 Project Overview

This tool takes a website URL as input and performs multiple phishing detection checks. It evaluates the URL using factors like domain age, suspicious content, use of short links, and more.

After the analysis, the tool:
- Assigns a **phishing score out of 100**
- Provides a **safety verdict** (Safe, Suspicious, or Phishing)
- Automatically saves reports in `.txt`, `.json`, and `.csv` formats for reference and logging.

---

## 🧠 How It Works

1. **User enters a URL**.
2. The system performs the following checks:
   - Domain age (via WHOIS)
   - Use of known URL shorteners
   - Suspicious keywords in the page title and body
   - Presence and behavior of HTML forms
   - URL structure analysis (length, symbols, HTTPS, IP addresses)
3. Based on the checks, a **phishing suspicion score** is calculated.
4. A clear verdict is shown to the user.
5. A report is generated and saved in the `reports/` folder.

---

## 🧩 File Structure

### `main.py`
- Entry point of the program
- Handles user interaction via a CLI menu
- Calls analysis and reporting functions

### `detector.py`
- Contains the core logic for phishing detection
- Uses libraries like `requests`, `bs4`, and `whois`
- Functions include:
  - `website_age()`
  - `is_short_link()`
  - `find_bad_words()`
  - `forms_send_outside()`
  - `get_score()` — calculates phishing likelihood based on flags

### `report.py`
- Handles output/report generation
- Saves reports in:
  - `.txt` (human-readable format)
  - `.json` (structured machine-readable format)
  - `.csv` (cumulative report log)

---

## 📊 Sample Output

🔍 PHISHING DETECTION TOOL
🌐 Enter the URL to analyze: http://example.com
📌 Domain Name: example.com
📅 Domain Age: 2 month(s)
🔗 Is Shortened Link: No
🚨 Suspicious content found in body!
🧠 Phishing Score: 65 / 100
📊 Result: ⚠️ SUSPICIOUS — Be cautious. Some red flags found.
💾 Report saved in TXT, JSON, and CSV formats.

yaml
Copy
Edit

---

## 🛠️ How to Run

### 📦 Requirements
Install dependencies using pip:
```bash
pip install requests beautifulsoup4 python-whois
▶️ Run the tool:
bash
Copy
Edit
python main.py
📁 Output Files
All reports are saved in the /reports folder:

report_YYYY-MM-DD_HH-MM-SS.txt — Human-readable report

report_YYYY-MM-DD_HH-MM-SS.json — Structured JSON report

summary_reports.csv — Aggregated log of all scans

🎯 Use Cases
Security awareness training

InfoSec course projects

URL analysis for phishing symptoms

Building baseline knowledge of phishing indicators

📌 Credits
This project was created for academic purposes as part of an Information Security course.

⚠️ Disclaimer
This tool uses heuristic checks and is not meant to replace professional phishing detection or threat intelligence platforms. False positives/negatives may occur.

💡 Want to Improve It?
Let me know if you'd like:

🎖️ Badges (Python version, MIT license, etc.)

📦 .gitignore file

🖼️ GUI interface version

🔄 Install/setup script

Open to suggestions and collaboration!

yaml
Copy
Edit

---


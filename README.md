# SMISHING ANALYZER 🚨

A fun and functional C++ program to sniff out spammy, phishing, or shady SMS messages before they bite!

---

## 🌟 Features

* **Keyword Detective**: Finds spammy keywords like `win`, `prize`, `urgent`, `bank`, etc.
* **Link Hunter**: Extracts links and flags suspicious domains.
* **Sender Sleuth**: Detects numeric or generic senders and assigns a reputation.
* **Risk Score**: Calculates a risk score based on content, links, and sender.
* **Multi-format Reports**: TEXT, JSON, CSV—your choice!
* **Report History**: Peek at past reports anytime.
* **Encryption/Decryption**: Caesar cipher keeps your reports "safe".
* **User Feedback**: Let the system know if it nailed spam detection.

---

## 🛠 Classes

* `SMSAnalyzer`: Abstract base class for SMS analysis.
* `KeywordMatcher`: Scans for suspicious keywords.
* `LinkAnalyzer`: Extracts and evaluates links.
* `SenderAnalyzer`: Checks sender type and reputation.
* `Reporter`: Combines all analyses and generates multi-format reports.
* `EncryptionModule`: Caesar cipher encryption/decryption.
* `UserFeedback`: Records user judgments.

---

## 🚀 How to Run

1. Compile:

```bash
g++ smishing_analyzer.cpp -o SMSAnalyzer -std=c++17
```

2. Run:

```bash
./SMSAnalyzer
```

3. Follow the main menu to create reports, encrypt/decrypt, save, and provide feedback.

---

## 🎛 Main Menu

```
========================================
||           MAIN MENU                 ||
========================================
|| 1. Create New Report                ||
|| 2. Show Latest Report (TEXT)        ||
|| 3. Show Latest Report (JSON)        ||
|| 4. Show Latest Report (CSV)         ||
|| 5. Encrypt Latest Report            ||
|| 6. Decrypt Last Encrypted Report    ||
|| 7. Save Latest Report to File       ||
|| 8. View Past Reports                ||
|| 9. User Feedback                    ||
|| 0. Exit                             ||
========================================
Choose: 
```

---

## 📝 Workflow Example

1. Input SMS content, sender ID, timestamp.
2. System analyzes keywords, links, and sender.
3. Generates and displays the risk report.
4. Encrypt, decrypt, or save reports as needed.
5. Provide user feedback for system improvement.

---

## ⚠ Notes

* OOP concepts: **inheritance**, **polymorphism**, **encapsulation**, **friend classes**.
* Caesar cipher is for demo purposes only.
* Suspicious domains list is customizable in `LinkAnalyzer`.

---

Made with ❤️ and a pinch of paranoia to keep your SMS safe!

🌟Collaborators🌟:
- Heena Farheen Kolimi
- A Salai Neranjana
- Samridhi Rauthan

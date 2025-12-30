# 🎣 CyberFish: The Phishing Training Simulator 🐟

Welcome to **CyberFish**! This powerful, user-friendly tool is designed exclusively for **educational purposes** and **authorized security awareness training**.

CyberFish enables you to simulate realistic phishing attacks in a safe, controlled environment. It's perfect for training yourself or your team to identify and avoid phishing threats without real-world risks.

---

## 🌟 Key Features

- 🖥️ **Intuitive GUI:** A clean, modern graphical interface for seamless operation.
- 🎭 **Realistic Phishing Templates:** Serve convincing fake login pages (e.g., Google, Outlook) to test user vigilance.
- 🌐 **Public Access via Cloudflare Tunnel:** Automatically creates a secure public URL, making your training pages accessible from anywhere on the internet.
- 📧 **Integrated Email Campaigns:** Craft and send custom phishing emails to target lists directly from the application.
- 🔗 **Advanced URL Masking:** Generate legitimate-looking links (e.g., `drive.google.com-security-update@...`) to enhance simulation realism.
- 📊 **Real-time Interaction Logging:** Monitor live submissions, capturing IP addresses, user-agents, and emails.
- 🛡️ **Secure Credential Handling:** Passwords are **never stored in plaintext**; they are immediately hashed to ensure participant safety and data privacy. All logs are encrypted.
- 📈 **Session Reporting:** Generate comprehensive PDF, CSV, or TXT reports of your training campaign results.

---

## 🛠️ Prerequisites

Before you begin your training simulation, ensure you have:

1.  **Python 3.10 or newer** installed on your system. [Download Python Here](https://www.python.org/downloads/).
2.  An active **Internet Connection** (essential for Cloudflare tunneling and email sending).

---

## 📥 Installation Guide

Follow these steps to set up CyberFish:

### 1. Clone the Repository

Download the project to your local machine:

```bash
git clone https://github.com/HyperActivated2046/CyberFish
cd CyberFish
```

### 2. Setting up CyberFish

Starting CyberFish is a breeze! Just click on:
`Run Me to Start.bat`

### 2.5 Launching CyberFish Manually

If, however, you'd like to launch CyberFish manually, it's highly recommended to use a virtual environment:

**💻 Windows:**

```bash
python -m venv venv
.\venv\Scripts\activate
pip install -r resources/requirements.txt
```

**🍎 macOS / 🐧 Linux:**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r resources/requirements.txt
```

---

## 🎒 Portable Mode (No Python Required)

For environments without Python, you can create a standalone executable:

1.  On a machine with Python installed, double-click **`Build Exe.bat`**.
2.  The script will install `PyInstaller` and compile the application.
3.  Once complete, navigate to the new **`Release`** folder.
4.  You will find **`CyberFish.exe`**, which can be copied and run on any Windows computer without a Python installation.

---

## 📖 User Guide: How to Use CyberFish

The application is divided into 4 intuitive tabs. Here is how to master them:

### 1️⃣ Server Tab (The Command Centre)

This is your home base.

- **Start Server + Tunnel:** Click this to launch your website. It takes a few seconds to connect to Cloudflare.
- **Status Light:**
  - 🔴 **Red:** Stopped.
  - 🟡 **Yellow:** Starting up...
  - 🟢 **Green:** Live and ready!
- **Copy Public URL:** Once the light is green, click this to copy your live link to the clipboard.
- **Status Log:** A live feed of what's happening under the hood.

### 2️⃣ Redirection & Templates Tab (The Disguise)

Choose what your victims see.

- **Template:** Select a pre-made login page (e.g., "Google-Mobile") or upload your own HTML file.
- **Action After Submission:**
  - **Redirect:** Send them to a real website (like google.com) after they "log in", so they don't suspect a thing.
  - **Instant Feedback:** Show a scary "YOU HAVE BEEN PHISHED" warning page immediately. Great for training!
- **URL Masker:** Paste your public link here to generate a tricky short link that looks like a legitimate domain (e.g., `drive.google.com`).

### 3️⃣ Email Tab (The Bait)

Send your training emails directly from the app.

- **SMTP Settings:** You need an email account to send from.
  - _Tip:_ If using Gmail, you **MUST** use an **App Password**. Your normal password will not work.
  - [Click here for Gmail App Password guide](https://support.google.com/accounts/answer/185833).
- **Compose:** Write your subject and body. Paste your masked link here!
- **Targets:** List the email addresses of your trainees (one per line).

### 4️⃣ Logs Tab (The Catch)

See who fell for the bait.

- **Submissions List:** Shows the Time, IP Address, and Email of everyone who submitted data.
- **Details:** Click any row to see more info, like the browser they used.
- **Export:** Save your report as a **PDF**, **CSV**, or **TXT** file to present to your team or boss.

---

## ⚠️ Legal & Ethical Disclaimer

**PLEASE READ CAREFULLY:**

> 🛑 **CyberFish is for EDUCATIONAL and AUTHORIZED testing purposes only.**

- **Do not** use this tool to target networks or individuals without explicit, written permission.
- **Do not** use this for malicious purposes.
- The developers of CyberFish assume **no liability** and are not responsible for any misuse or damage caused by this program.

**Practice Safe Computing!** 🛡️

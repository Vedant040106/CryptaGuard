# CryptaGuard 🛡️

A comprehensive cybersecurity awareness and defense platform built with Flask. CryptaGuard combines real-time threat analysis tools, AI-powered security guidance, and encrypted communication — all wrapped in a cyberpunk-themed interface.

---

## 🚀 Features

### 🤖 AI Security Agent
An intelligent cybersecurity chatbot powered by **Google Gemini 2.5 Flash**. Ask real-time security questions and receive concise, professional-grade responses.

### 🔐 Password Strength Analyzer
Test and evaluate the strength of your passwords with instant visual feedback and improvement suggestions.

### 🧪 Malware Sandbox
Upload files for static threat analysis. The engine performs:
- **SHA-256 cryptographic hashing** for file fingerprinting.
- **EICAR test signature detection** for antivirus validation.
- **Dangerous extension flagging** (`.exe`, `.bat`, `.vbs`, `.scr`, etc.).

### 🖼️ Steganography Lab
Hide and reveal secret messages inside images using **Least Significant Bit (LSB)** encoding.
- **Encode**: Embed a hidden text payload into any image.
- **Decode**: Scan an image to extract hidden messages.

### 🔗 URL Analyzer
Perform real-time URL health checks — detect redirects, verify content types, and check if a link is online or offline.

### 📰 Live Cyber News Feed
Stay updated with the latest cybersecurity news, pulled directly from **The Hacker News** RSS feed.

### 💬 Encrypted Chat
Secure peer-to-peer communication system with:
- User search & friend request system.
- Real-time messaging between accepted contacts.
- Full message history.

### 📊 Activity Logs & History
A personal audit trail that tracks every action across all modules — file scans, chats, tool usage, and more.

### 🔑 Secure Authentication
- User registration with **hashed passwords** (Werkzeug).
- Login / Logout with Flask session management.
- **Forgot Password** flow via security question verification.

---

## 🛠️ Tech Stack

| Layer          | Technology                                     |
| -------------- | ---------------------------------------------- |
| **Backend**    | Python 3, Flask                                |
| **Database**   | MySQL                                          |
| **Frontend**   | HTML5, CSS3 (Cyberpunk Theme), JavaScript      |
| **AI**         | Google Gemini 2.5 Flash                        |
| **Security**   | SHA-256 Hashing, Werkzeug Password Hashing     |
| **Image Proc** | OpenCV, NumPy (Steganography Engine)           |
| **Data Feeds** | Feedparser (RSS), Requests (HTTP)              |

---

## 📁 Project Structure

```
CryptaGuard/
├── app.py               # Main Flask application & API routes
├── config.py            # App configuration (DB, API keys)
├── stego_engine.py      # LSB Steganography encode/decode engine
├── database.sql         # MySQL schema setup script
├── requirements.txt     # Python dependencies
├── static/              # CSS, JS, images, uploads
├── templates/           # Jinja2 HTML templates
│   ├── landing.html     # Landing page
│   ├── login.html       # Login & Registration
│   ├── index.html       # Main Dashboard
│   ├── forgot_password.html
│   ├── verify_question.html
│   └── reset_password.html
└── README.md
```

---

## 📦 Getting Started

### Prerequisites

- **Python 3.8+**
- **MySQL Server** (via XAMPP, WAMP, or standalone)
- A **Google Gemini API Key** ([Get one here](https://aistudio.google.com/app/apikey))

### 1. Clone the Repository

```bash
git clone https://github.com/Vedant040106/CryptaGuard.git
cd CryptaGuard
```

### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

> You may also need to install OpenCV and NumPy for the Steganography Lab:
> ```bash
> pip install opencv-python numpy google-generativeai feedparser requests
> ```

### 3. Set Up the Database

Import the schema into your MySQL server:

```bash
mysql -u root -p < database.sql
```

Or import `database.sql` manually via **phpMyAdmin** / **MySQL Workbench**.

### 4. Configure the App

Edit `config.py` with your credentials:

```python
GEMINI_API_KEY = 'your_gemini_api_key'
MYSQL_HOST     = 'localhost'
MYSQL_USER     = 'root'
MYSQL_PASSWORD = 'your_password'
MYSQL_DB       = 'cryptaguard'
```

### 5. Run the Server

```bash
python app.py
```

Access at **http://localhost:5000**

---

## 🚀 Deployment (Render)

1. Push the repo to GitHub.

2. Create a **Web Service** on [Render](https://render.com) and connect your repo.

3. Set the following **environment variables** in the Render dashboard:

   | Variable         | Value                     |
   | ---------------- | ------------------------- |
   | `SECRET_KEY`     | _(auto-generated)_        |
   | `GEMINI_API_KEY` | Your Google Gemini key    |
   | `MYSQL_HOST`     | Your MySQL host           |
   | `MYSQL_USER`     | Your MySQL user           |
   | `MYSQL_PASSWORD` | Your MySQL password       |
   | `MYSQL_DB`       | `cryptaguard`             |

4. Render will auto-detect the `Procfile` and run `gunicorn wsgi:app`.

> **Tip:** You can also use the included `render.yaml` blueprint for one-click setup.

---

## 📸 Screenshots

> _Coming soon_

---

## 📄 License

This project is built for educational and academic purposes.

---

## 👤 Author

**Vedant** — [GitHub](https://github.com/Vedant040106)

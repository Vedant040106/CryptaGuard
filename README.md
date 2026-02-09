# CryptaGuard 🛡️

CryptaGuard is a comprehensive cybersecurity awareness platform designed to educate users on digital threats like Phishing, Malware, and Password Security.

## 🚀 Features

- **AI Security Agent**: An intelligent chatbot for real-time security advice (Powered by Google Gemini).
- **Password Strength Analyzer**: Tools to test and improve credential security.
- **Educational Modules**: Interactive guides on avoiding digital scams.
- **QR Code Scanner**: Analyze QR codes for malicious links.
- **Malware Sandbox**: Simulate file analysis safely.
- **Encrypted Chat**: Secure communication channel.

## 🛠️ Tech Stack

- **Backend**: Python (Flask, MySQL)
- **Frontend**: HTML5, CSS3 (Cyberpunk Theme), JavaScript
- **AI Integration**: Google Gemini 1.5 Flash
- **Security**: SHA-256 Hashing, Input Sanitization

## 📦 How to Run

1. **Clone the repo**

   ```bash
   git clone https://github.com/Vedant040106/CryptaGuard.git
   cd CryptaGuard
   ```

2. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure the App**
   - Create a `config.py` file (or rename `config.example.py` if available).
   - Add your `MySQL` credentials and `GEMINI_API_KEY`.

4. **Run the Database Script**
   - Import `database.sql` into your MySQL server.

5. **Start the Server**
   ```bash
   python app.py
   ```
   Access at `http://localhost:5000`

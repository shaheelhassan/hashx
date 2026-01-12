# <p align="center">🛡️ HASHX - Secure Crypto Suite</p>

<p align="center">
  <img src="hashx_banner.png" alt="HASHX Banner" width="800">
</p>

<p align="center">
  <strong>A premium, high-performance desktop application for industrial-grade hashing, encryption, and digital signatures.</strong>
</p>

---

## ✨ Features

### 🔑 Hashing & Integrity
- **Multi-Algorithm Support**: MD5, SHA-1, SHA-256, and SHA-512.
- **Salting**: Built-in support for custom salts to prevent rainbow table attacks.
- **File Integrity**: Verify downloads and software packages with chunked file hashing.

### 🔐 Advanced Encryption
- **Symmetric (AES-256)**: Secure messaging using the Fernet (AES-GCM) standard.
- **Asymmetric (RSA-2048)**: Industrial RSA with OAEP padding for secure key exchange.
- **Key Derivation**: Robust password-based keys via PBKDF2-HMAC-SHA256 with 480,000 iterations.

### 🖊️ Digital Signatures
- **RSA-PSS Signing**: Digitally sign messages to prove authenticity.
- **Verification**: Instantly verify signatures to ensure no tampering occurred.

### 🛠️ Professional Utilities
- **File Armor**: Securely encrypt and decrypt physical files on your local machine.
- **Strong Key Gen**: Generate cryptographically secure passwords up to 128 characters.
- **Base64 Toolset**: Integrated encoder and decoder for data transmission safety.

### 🎨 Premium Experience
- **Flat UI White Edition**: A clean, modern aesthetic designed for maximum clarity.
- **Context Awareness**: Global right-click menu (Copy, Paste, Cut, Select All).
- **One-Click Utility Bar**: Quick buttons for copying results and clearing the workspace.

---

## 🚀 Getting Started

### Prerequisites
- Python 3.10 or higher
- `pip` package manager

### Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/HASHX.git
   cd HASHX
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application
Launch the suite using the desktop-ready launcher:
```bash
python run.py
```

---

## 📂 Project Structure
```bash
HASHX/
├── src/
│   ├── crypto_utils.py   # Cryptographic engine ⚙️
│   └── gui.py            # Flat UI White interface 🎨
├── run.py                # Main launcher 🚀
├── requirements.txt      # System dependencies 📦
└── README.md             # Documentation 📖
```

---

## 🛡️ Security Architecture
- **Authenticated Encryption**: Uses AES-128 in CBC mode with HMAC for symmetric data.
- **Entropy Source**: All random values are sourced from `os.urandom` (system-grade entropy).
- **Modern Padding**: Implements OAEP for RSA and PSS for signatures, avoiding legacy vulnerabilities.

---

<p align="center">
  Designed with ❤️ for privacy and security.
</p>

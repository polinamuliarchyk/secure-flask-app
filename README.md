# Data Protection Mechanisms Analysis and Implementation

**Author:** Palina Muliarchyk  
**Project Type:** Engineer's Thesis

## Project Overview
A secure educational platform developed in Python. This project serves as a practical demonstration of **Defense in Depth** mechanisms, specifically implementing:
* **MFA** (Time-based One-Time Password [TOTP] + Email verification)
* **RBAC** (Role-Based Access Control)
* Data Encryption and Password Hashing
* **Graylog (SIEM)** Integration for security monitoring
* HTTP Security Headers

## System Requirements
* Python 3.8+
* SQLite Database
* Web browser with JavaScript enabled

## Installation and Setup

### 1. Clone the repository
Extract the project files into your chosen directory or clone the repo.

### 2. Create a virtual environment (Recommended)
``` bash
python -m venv venv
```

#### Activation:
* Windows: venv\Scripts\activate
* Linux/Mac: source venv/bin/activate

### 3. Install dependencies
``` bash
pip install -r requirements.txt
```

### 4. Environment Variables Configuration
Create a .env file in the root directory based on the template below:
```
SECRET_KEY=your_very_long_secret_key
fernet_key=key_generated_by_fernet
MAIL_USERNAME=your_email@gmail.com
MAIL_PASSWORD=your_app_password
ADMIN_USERNAME=admin
ADMIN_PASSWORD=strong_admin_password
ADMIN_EMAIL=admin@example.com
```
* Note: To generate a secure Fernet key, use the following Python commands:
``` python
from cryptography.fernet import Fernet
Fernet.generate_key()
```

### 5. Database Initialization
``` bash
flask db init
flask db migrate
flask db upgrade
```

### 6. Run the Application
``` bash
python run.py
```

The application will be available at: https://127.0.0.1:5000/

SECURITY NOTE: The application runs on a Self-Signed SSL certificate. Your browser will display a security warning — you need to proceed by adding a security exception.

### 7. Graylog (SIEM) Setup
Requires Docker or an external Graylog instance configured to listen on UDP (port 12201). The Graylog IP address must be configured in the extensions.py or .env file.
# 🧠 IntelGraph — OSINT Cyber Intelligence Platform

IntelGraph is a **graph-based OSINT (Open Source Intelligence) investigation platform** designed for cybersecurity analysts, investigators, and researchers.

It allows users to map entities like **IP addresses, domains, emails, social profiles, and images**, connect relationships between them, and generate structured intelligence reports.

---

## 🚀 Key Capabilities

* 🔗 **Graph-Based Intelligence Mapping**

  * Visualize entities as nodes and relationships as edges
  * Interactive canvas powered by Cytoscape.js

* 🕵️ **OSINT Data Correlation**

  * Link IPs, domains, emails, people, and URLs
  * Identify hidden relationships and clusters

* 🧾 **Evidence & Case Building**

  * Attach notes and tags to entities
  * Maintain investigation timelines
  * Export structured intelligence reports

* 🛡️ **Security-Hardened Backend**

  * Bcrypt password hashing
  * CSRF protection (Flask-WTF)
  * Rate limiting (Flask-Limiter)
  * Brute-force protection with progressive lockouts
  * Audit logging of security events

* 👨‍💼 **Role-Based Access Control**

  * Admin / User system
  * Account locking, impersonation, and recovery tools

---

## 🧠 Use Cases

* Cybercrime investigations
* OSINT research and profiling
* Threat intelligence analysis
* Digital identity mapping
* Incident investigation

---

## 🏗️ Tech Stack

**Backend**

* Python (Flask)
* SQLAlchemy (SQLite)
* Flask-Login, Flask-Bcrypt
* Flask-WTF, Flask-Limiter

**Frontend**

* HTML, CSS, Vanilla JavaScript
* Cytoscape.js (graph engine)

---

## ⚙️ Setup

```bash
git clone https://github.com/Aashish-kumar77/IntelGraph.git
cd IntelGraph

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

python3 -c "from app import app, db; app.app_context().push(); db.create_all()"

export INTELGRAPH_SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))")

python app.py
```

---

## 🔐 Security Features

* Progressive brute-force protection
* Session timeout and secure cookies
* CSRF protection on all forms
* HTTP security headers (CSP, HSTS, etc.)
* Audit logging of all critical actions

---

## 📊 Future Roadmap

* [ ] Real-time collaboration (WebSockets)
* [ ] API-based OSINT integrations (Shodan, HaveIBeenPwned)
* [ ] Automated entity enrichment
* [ ] Graph AI analysis (pattern detection)
* [ ] Two-Factor Authentication (2FA)

---

## 👨‍💻 Author

Aashish Kumar

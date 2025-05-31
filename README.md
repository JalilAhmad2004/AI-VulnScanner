# Automated-Vulnerability-Scanner-with-AI-Powered-Classification-and-Remediation

<p align="center">
  <img src="https://img.shields.io/badge/Flask-000000?style=for-the-badge&logo=flask&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Random_Forest-4B8BBE?style=for-the-badge" />
  <img src="https://img.shields.io/badge/T5_Transformer-008080?style=for-the-badge" />
  <img src="https://img.shields.io/badge/OpenVAS-5C4E77?style=for-the-badge" />
  <img src="https://img.shields.io/badge/HTML_CSS_JS-FFD43B?style=for-the-badge&logo=html5&logoColor=black" />
</p>

---

## 🚀 Project Overview

This project automates the **detection**, **severity classification**, and **remediation recommendation** of software vulnerabilities using:

- **OpenVAS** for vulnerability scanning  
- **Random Forest ML model** for severity classification  
- **Fine-tuned T5 transformer** for AI-powered remediation generation  
- A web-based UI powered by **Flask** for easy interaction  

The system streamlines vulnerability management by providing actionable insights from scan results, helping security professionals respond faster and smarter.

---

## 📁 Repository Structure

```

project\_code/
├── checkup\_database/         # Dataset and database files used for training/classification
├── model\_results/            # Saved model evaluation reports and outputs
├── models/                   # Trained ML and transformer model files
├── scan\_results/             # Raw and parsed OpenVAS scan results (CSV/JSON)
├── static/                   # Frontend static files (CSS, JS, images)
├── templates/                # Flask HTML templates for web UI
├── app.py                    # Main Flask application
├── openvas\_scan.py           # OpenVAS scanning automation scripts

````

---

## 🛠 Features

- **Automated Scanning:** Launch scans against target IPs via OpenVAS using CLI and Python integration.  
- **Data Enrichment:** Extract CVE IDs, CVSS scores, access vectors, exploit info, and more from scan data.  
- **Severity Classification:** Predicts vulnerability severity (Low, Medium, High, Critical) using Random Forest with SBERT embeddings.  
- **Remediation Generation:** Generates tailored human-readable remediation steps via a fine-tuned T5 transformer model.  
- **User-Friendly Web UI:** Easily initiate scans, view detailed reports, and get remediation suggestions from a hacker-themed interface.

---

## 📊 Model Performance

| Model                   | Metric           | Score |
|-------------------------|------------------|-------|
| Severity Classification | Accuracy         | 98%   |
|                         | F1-Score (Macro) | 0.97  |
| Remediation Generation  | ROUGE-1          | 0.597 |
|                         | ROUGE-L          | 0.618 |

Detailed evaluation reports are available in the `model_results/` folder.

---

## 🧩 Installation & Usage

1. **Clone this repo:**

   ```bash
   git clone https://github.com/JalilAhmad2004/automated-vuln-scanner.git
   cd automated-vuln-scanner/project_code

2. **Create and activate Python environment:**

   ```bash
   python3 -m venv venv
   source venv/bin/activate   # On Windows use: venv\Scripts\activate
   ```

3. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Flask app:**

   ```bash
   python app.py
   ```

5. **Open your browser:**
   Visit `http://localhost:5000` to access the scanning dashboard.

---

## 🧑‍💻 How It Works

> **Note:** The trained model files are large (~300 MB) and are not included here.  
> If you need the models, please contact me via email at **ahmadjaleel110@gmail.com**.

* Enter target IP and start an OpenVAS scan.
* Once the scan completes, view raw scan results.
* Trigger the severity classification to label vulnerabilities.
* Generate AI-powered remediation steps tailored for each vulnerability.
* Export results or use for further analysis.

---

## 📂 Dataset Information

* **Severity Classification Dataset:** Over 200,000 CVE records from NVD and ExploitDB enriched with metadata and SBERT embeddings. Stored in `checkup_database/`.
* **Remediation Dataset:** Contains remediation texts scraped and curated for 14,000+ vulnerabilities, used for fine-tuning the T5 model.

---

## 🔮 Future Work

* Integrate real-time NVD API for up-to-date vulnerability info.
* Upgrade SBERT embeddings with a domain-specific language model fine-tuned on MITRE CVE data.
* Develop a multi-host scanning dashboard with trend analytics.
* Improve UI/UX and extend remediation suggestions for zero-day vulnerabilities.

---

## 👥 Team Members

* [@UmerFarooq](https://github.com/0ri4x) (I221661)  
* [@JalilAhmad](https://github.com/JalilAhmad2004) (I221635)  
* [@AleenaFatima](https://github.com/aleenafatimaqureshi) (I222353)

---

## 📄 Project Report & Presentation

- [Project Report PDF](docs/report.pdf)  
- [Presentation PPTX](docs/presentation.pptx)

---

## 🎥 Video Demonstration

Watch the project demo video on LinkedIn here:  
[LinkedIn Video Demo](https://www.linkedin.com/posts/jalil-ahmad-b0b0b4257_cybersecurity-machinelearning-ai-activity-7334645552078336001-4Xa0?utm_source=social_share_send&utm_medium=member_desktop_web&rcm=ACoAAD8yTDsBVy8nzQlZvOxeT4nxTxOQzmCYd6Q)

---

## ⭐ Contributions and Feedback Welcome!

Feel free to open issues or submit pull requests to help improve this project.
This repository is open for collaboration in vulnerability management and AI-assisted cybersecurity.

---

*Powered by OpenVAS, Machine Learning, and Transformers — Bridging Detection and Remediation with AI.*

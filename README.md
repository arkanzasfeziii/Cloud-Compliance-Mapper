# ☁️ Cloud Compliance Mapper

**Version:** 1.0.0  
**Author:** arkanzasfeziii  
**License:** MIT  

A comprehensive compliance assessment tool for mapping cloud configurations to **NIST SP 800-53**, **ISO 27001**, and **CIS Benchmarks** across **AWS**, **Azure**, and **GCP**.

---

## ⚠️ Legal & Security Warning

> **IMPORTANT:** This tool requires valid cloud credentials with read/list permissions. It is designed for **AUTHORIZED compliance auditing of YOUR OWN cloud accounts ONLY**.
>
> - Compliance results are **INDICATIVE** and NOT a substitute for formal audits or certifications.
> - Scanning without authorization is **ILLEGAL**.
> - You must have explicit permission for all scanned accounts.
> - The author assumes **NO LIABILITY** for misuse or reliance on compliance results.

---

## 🚀 Features

- **Multi-Cloud Support:** AWS, Azure, and Google Cloud Platform (GCP).
- **Multi-Framework Mapping:**
  - NIST SP 800-53 (Rev. 5)
  - ISO 27001:2022 Annex A
  - CIS Benchmarks (AWS, Azure, GCP)
- **Flexible Output:** Console, JSON, CSV, and HTML reports.
- **Risk Severity:** Findings categorized by Critical, High, Medium, Low, and Info.
- **Detailed Logging:** Verbose and debug modes available.

---

## 📦 Installation

### Prerequisites
- Python 3.8+
- Cloud CLI credentials configured (AWS CLI, Azure CLI, or GCP SDK)

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/arkanzasfeziii/cloud-compliance-mapper.git
   cd cloud-compliance-mapper
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

🛠 Usage

Basic Command
```bash
python cloudcompliancemapper.py --provider <aws|azure|gcp|all> --framework <nist|iso|cis|all>
```

Examples

1. Assess AWS against all frameworks:
   ```bash
   python cloudcompliancemapper.py --provider aws --framework all
   ```
2. Check NIST controls for AWS and save HTML report:
   ```bash
   python cloudcompliancemapper.py --provider aws --framework nist --output html --output-file nist_report.html
   ```
3. Check CIS benchmarks for Azure:
   ```bash
   export AZURE_SUBSCRIPTION_ID="your-subscription-id"
   python cloudcompliancemapper.py --provider azure --framework cis
   ```
4. Multi-cloud ISO 27001 assessment (JSON output):
   ```bash
   python cloudcompliancemapper.py --provider all --framework iso --output json --output-file iso_compliance.json
   ```
5. Filter by Control Family (e.g., NIST Access Control):
   ```bash
   python cloudcompliancemapper.py --provider aws --framework nist --control-family AC
   ```
🔐 Configuration
   
  Ensure your environment is authenticated before running scans:

  AWS: Configure via aws configure or environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY).

  Azure: Set AZURE_SUBSCRIPTION_ID and authenticate via az login.

  GCP: Set GCP_PROJECT_ID and ensure Application Default Credentials are configured.

📄 Output Formats

  Console: Real-time summary with Rich UI (if available).

  JSON: Machine-readable format for integration with other tools.

  CSV: Suitable for spreadsheet analysis.

  HTML: Visual report with compliance scores and status tables.

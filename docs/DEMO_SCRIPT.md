# MailForensics — Demonstration Script & Walkthrough

## Step-by-Step Presentation Guide

### 1. Ingesting Controlled Lab Samples
1. Navigate to **Dashboard** (`/dashboard`).
2. Click **Seed Controlled Lab Demo Samples**.
3. Observe real database statistics update instantly across the KPI metrics cards.

### 2. Investigating Multi-Indicator Phishing
1. Navigate to **Email Samples** (`/emails`).
2. Click **Investigate** on `MULTI_INDICATOR_PHISHING_EMAIL`.
3. Review the **Overview** tab:
   - Automated Risk: **HIGH / CRITICAL** score.
   - Observe **SPF FAIL**, **DKIM FAIL**, **DMARC FAIL**.
4. Open the **Received Chain** tab:
   - Observe ordered transit hops and delay timing.
5. Open the **URLs** tab:
   - Identify raw IP address host URL (`http://203.0.113.50/...`).
6. Open the **Attachments** tab:
   - Inspect static metadata for `Account_Verification_Form.xlsm`. Note SHA-256 hash.

### 3. Setting Analyst Verdict & Generating Report
1. Select **PHISHING** from the Analyst Verdict form and add investigation notes.
2. Click **Download PDF Report**.
3. Inspect the executive SOC ReportLab PDF document.

### 4. Incident Case Creation & Audit Trail
1. Click **Create Case** to bind the email to an incident.
2. View **Audit Logs** (`/audit`) to confirm immutable logging of the verdict change and report generation.

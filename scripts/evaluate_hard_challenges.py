"""Hard Challenges & Edge Case Security Evaluation Suite for CodeGuardian AI."""

import json
import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.security_engine import analyze_diff

CHALLENGES = {
    # 1. Command Injection via child_process & os.popen
    "command_injection_variants": """diff --git a/server/runner.py b/server/runner.py
--- a/server/runner.py
+++ b/server/runner.py
@@ -10,3 +10,6 @@ def run_pipeline(cmd, user_repo):
-    pass
+    import os, subprocess
+    output = os.popen(f"git clone {user_repo}").read()
+    subprocess.check_output(f"npm test {cmd}", shell=True)
+    return output
""",

    # 2. Insecure PyTorch Model / Weights Loading (RCE in ML pipelines)
    "pytorch_unsafe_model_load": """diff --git a/ml/pipeline.py b/ml/pipeline.py
--- a/ml/pipeline.py
+++ b/ml/pipeline.py
@@ -15,2 +15,4 @@ def load_checkpoint(weights_path):
-    return torch.load(weights_path, weights_only=True)
+    # Unsafe checkpoint load without weights_only lock (arbitrary pickle execution)
+    return torch.load(weights_path, weights_only=False)
""",

    # 3. High-Value AI & Cloud API Keys (OpenAI, Anthropic, HuggingFace, Stripe, DB URI)
    "modern_api_secrets": """diff --git a/config/services.py b/config/services.py
--- a/config/services.py
+++ b/config/services.py
@@ -5,2 +5,7 @@ class CloudConfig:
-    openai_key = os.getenv("OPENAI_API_KEY")
+    openai_api_key = "sk-proj-9aB2cD3eF4gH5iJ6kL7mN8oP9qR0sT1uV2wX3yZ4aB5cD6eF7gH8"
+    anthropic_api_key = "sk-ant-api03-abcdef1234567890abcdef1234567890abcdef12345678"
+    huggingface_token = "hf_abcdefghijklmnopqrstuvwxyz01234567"
+    stripe_secret = "sk_test_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
+    database_url = "postgresql://admin:P@ssw0rd12345!@db.internal.corp:5432/prod_db"
""",

    # 4. SSRF via Webhook Callback & httpx / aiohttp
    "ssrf_webhook_dispatcher": """diff --git a/webhooks/dispatcher.py b/webhooks/dispatcher.py
--- a/webhooks/dispatcher.py
+++ b/webhooks/dispatcher.py
@@ -8,3 +8,5 @@ async def send_notification(event_data, webhook_url):
-    pass
+    import httpx
+    async with httpx.AsyncClient() as client:
+        resp = await client.post(webhook_url, json=event_data, timeout=10.0)
+    return resp.status_code
""",

    # 5. Tar Slip / Zip Slip Arbitrary File Overwrite (CWE-22)
    "zip_slip_archive_traversal": """diff --git a/archive/extractor.py b/archive/extractor.py
--- a/archive/extractor.py
+++ b/archive/extractor.py
@@ -12,3 +12,5 @@ def extract_bundle(archive_file, output_dir):
-    pass
+    import tarfile, zipfile
+    with tarfile.open(archive_file) as tar:
+        tar.extractall(path=output_dir)
""",

    # 6. Cryptographic Insecurity: AES ECB Mode & Weak Hashing in JWT
    "crypto_aes_ecb_mode": """diff --git a/crypto/vault.py b/crypto/vault.py
--- a/crypto/vault.py
+++ b/crypto/vault.py
@@ -10,3 +10,5 @@ def encrypt_payload(data, secret_key):
-    pass
+    from Crypto.Cipher import AES
+    cipher = AES.new(secret_key, AES.MODE_ECB)
+    return cipher.encrypt(data)
""",

    # 7. Server-Side Template Injection (SSTI) & Unsafe Jinja Filters
    "ssti_jinja_safe_filter": """diff --git a/views/profile.py b/views/profile.py
--- a/views/profile.py
+++ b/views/profile.py
@@ -14,3 +14,5 @@ def render_user_badge(username):
-    return render_template("badge.html", name=escape(username))
+    from flask import Markup, render_template_string
+    template = f"<div class='badge'>Welcome, {username}!</div>"
+    return render_template_string(template)
""",

    # 8. Node.js Command Injection via child_process.execSync
    "nodejs_child_process_exec": """diff --git a/scripts/deploy.js b/scripts/deploy.js
--- a/scripts/deploy.js
+++ b/scripts/deploy.js
@@ -5,3 +5,5 @@ function buildBranch(branchName) {
-    return;
+    const { execSync } = require('child_process');
+    const result = execSync(`git checkout ${branchName} && npm run build`);
+    return result.toString();
 }
""",

    # 9. Insecure CORS and Permissive Regex ReDoS
    "cors_and_redos": """diff --git a/api/router.py b/api/router.py
--- a/api/router.py
+++ b/api/router.py
@@ -8,3 +8,6 @@ def setup_middleware(app):
-    pass
+    from fastapi.middleware.cors import CORSMiddleware
+    app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)
+    email_validator = re.compile(r"^([a-zA-Z0-9_\\-\\.]+)@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.)|(([a-zA-Z0-9\\-]+\\.)+))+([a-zA-Z]{2,4}|[0-9]{1,3})(\\]?)$")
""",

    # 10. Multi-File Enterprise PR: Clean Changes + Embedded Vulnerability
    "enterprise_multifile_pr": """diff --git a/src/logger.py b/src/logger.py
--- a/src/logger.py
+++ b/src/logger.py
@@ -10,2 +10,3 @@ def log_event(name, level="INFO"):
-    print(f"[{level}] {name}")
+    import logging
+    logging.info(f"[{level}] {name}")
diff --git a/src/auth/token_service.py b/src/auth/token_service.py
--- a/src/auth/token_service.py
+++ b/src/auth/token_service.py
@@ -22,3 +22,5 @@ def generate_reset_token(user_id):
-    import secrets
-    return secrets.token_urlsafe(32)
+    import random
+    # Using pseudo-random numbers for password reset token
+    token = f"{user_id}-{random.random()}-{random.randint(1000, 9999)}"
+    return token
diff --git a/src/billing/invoice.py b/src/billing/invoice.py
--- a/src/billing/invoice.py
+++ b/src/billing/invoice.py
@@ -5,2 +5,4 @@ def format_invoice(total):
-    return f"${total:.2f}"
+    tax = total * 0.08
+    grand_total = total + tax
+    return f"${grand_total:.2f}"
"""
}

def evaluate_suite():
    print(f"============================================================")
    print(f"EVALUATING CODEGUARDIAN ON {len(CHALLENGES)} HARD CHALLENGES")
    print(f"============================================================\n")

    results = {}
    for name, diff in CHALLENGES.items():
        report = analyze_diff(diff)
        findings_count = len(report.findings)
        rule_ids = [f.rule_id for f in report.findings]
        titles = [f.title for f in report.findings]
        results[name] = {
            "verdict": report.verdict,
            "count": findings_count,
            "rules": rule_ids,
            "titles": titles
        }
        status_icon = "DETECTED" if findings_count > 0 else "MISSED"
        print(f"[{status_icon}] {name}: {findings_count} finding(s) ({', '.join(rule_ids) if rule_ids else 'None'})")
        for f in report.findings:
            print(f"    - [{f.severity}] {f.rule_id} ({f.file}:{f.line_start}) - {f.title}")

    print("\nSummary:")
    detected_count = sum(1 for r in results.values() if r["count"] > 0)
    print(f"Detected: {detected_count}/{len(CHALLENGES)} challenges")

if __name__ == "__main__":
    evaluate_suite()

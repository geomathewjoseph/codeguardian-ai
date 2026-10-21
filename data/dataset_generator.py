"""
CodeGuardian Dataset Synthesizer
Generates rich, diverse code diffs across Python, JavaScript/TypeScript, Go, and Rust
paired with expert structured JSON reviews (Security, Performance, Bugs, Unit Tests).
"""

import json
import random
import os
import sys
from pathlib import Path
from typing import Dict, Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.schemas import Finding, ReviewReport, SeverityCounts, UnitTestFixture
from app.security_engine import parse_unified_diff

SYSTEM_PROMPT = """You are CodeGuardian, an evidence-first local code reviewer.
Return one JSON object conforming to the CodeGuardian ReviewReport v2 contract. Every
finding must have a stable ID, category, severity, confidence, relative file path,
changed new-file line_start/line_end, source evidence, remediation, provenance, and
an explicit patch/test verification state. Counts must exactly equal the findings.
Do not report a finding for a clean change. Do not claim a patch or test was executed
unless execution output is provided. If evidence is insufficient, say so in the
summary rather than inventing source locations or exploit proof."""

# Curated seed scenarios spanning common real-world bugs, vulnerabilities, and clean PRs
SCENARIOS = [
    {
        "diff": """diff --git a/auth/login.py b/auth/login.py
index 45a1c2..89f3e1 100644
--- a/auth/login.py
+++ b/auth/login.py
@@ -12,4 +12,6 @@ def authenticate_user(db, username, password):
-    user = db.users.find_one({"username": username})
-    if user and bcrypt.checkpw(password.encode(), user["password_hash"]):
-        return create_jwt_token(user["id"])
+    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
+    user = db.execute(query).fetchone()
+    if user:
+        return create_jwt_token(user['id'])
     return None""",
        "review": {
            "summary": "Refactored user authentication to use raw SQL queries instead of ORM/bcrypt password verification.",
            "risk_level": "CRITICAL",
            "findings": [
                {
                    "file": "auth/login.py",
                    "type": "SECURITY",
                    "title": "SQL Injection & Plaintext Password Comparison",
                    "description": "User input is directly formatted into raw SQL allowing authentication bypass (e.g., ' OR '1'='1). Plaintext password comparison removes bcrypt password hashing.",
                    "suggested_fix": "- query = f\"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'\"\n+ cursor.execute(\"SELECT id, password_hash FROM users WHERE username = %s\", (username,))\n+ user = cursor.fetchone()\n+ if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):\n+     return create_jwt_token(user['id'])"
                }
            ],
            "unit_tests": "def test_sql_injection_attempt(client):\n    res = authenticate_user(db, \"admin' OR '1'='1\", \"randompass\")\n    assert res is None, 'SQL injection bypass succeeded!'",
            "verdict": "REQUEST_CHANGES"
        }
    },
    {
        "diff": """diff --git a/services/cache.py b/services/cache.py
index a21c33..b44f21 100644
--- a/services/cache.py
+++ b/services/cache.py
@@ -25,3 +25,7 @@ class MemoryCache:
     def get_or_set(self, key, fetch_func):
-        return self._cache.get(key) or self.set(key, fetch_func())
+        if key not in self._cache:
+            val = fetch_func()
+            self._cache[key] = val
+        return self._cache[key]""",
        "review": {
            "summary": "Modified cache lookup logic to avoid re-evaluating falsy cached values.",
            "risk_level": "LOW",
            "findings": [
                {
                    "file": "services/cache.py",
                    "type": "BUG",
                    "title": "Falsy Cache Invalidation Fixed",
                    "description": "The previous code used 'or', which caused cached falsy values (like 0, False, []) to execute fetch_func again. The new membership check fixes this.",
                    "suggested_fix": "# Looks good. Optional: add thread lock if used in multi-threaded environment."
                }
            ],
            "unit_tests": "def test_cache_stores_falsy_values():\n    cache = MemoryCache()\n    calls = 0\n    def fetch():\n        nonlocal calls\n        calls += 1\n        return 0\n    assert cache.get_or_set('count', fetch) == 0\n    assert cache.get_or_set('count', fetch) == 0\n    assert calls == 1",
            "verdict": "APPROVE"
        }
    },
    {
        "diff": """diff --git a/api/handlers/file_upload.ts b/api/handlers/file_upload.ts
index e991a0..112bc4 100644
--- a/api/handlers/file_upload.ts
+++ b/api/handlers/file_upload.ts
@@ -15,5 +15,5 @@ export async function handleUpload(req: Request, res: Response) {
-  const safeFilename = path.basename(req.file.originalname).replace(/[^a-zA-Z0-9._-]/g, '');
-  const dest = path.join('/var/app/uploads', safeFilename);
+  const targetPath = req.body.destination || '/var/app/uploads';
+  const dest = path.join(targetPath, req.file.originalname);
   await fs.promises.writeFile(dest, req.file.buffer);
   return res.json({ status: 'ok', path: dest });
 }""",
        "review": {
            "summary": "Permits client to specify arbitrary destination directory and uses unsanitized original filename for file uploads.",
            "risk_level": "CRITICAL",
            "findings": [
                {
                    "file": "api/handlers/file_upload.ts",
                    "type": "SECURITY",
                    "title": "Path Traversal & Arbitrary File Overwrite",
                    "description": "Client-controlled req.body.destination and unescaped req.file.originalname allow attackers to traverse directories (e.g., '../../etc/cron.d/') and overwrite system files.",
                    "suggested_fix": "- const targetPath = req.body.destination || '/var/app/uploads';\n- const dest = path.join(targetPath, req.file.originalname);\n+ const uploadDir = '/var/app/uploads';\n+ const safeName = crypto.randomUUID() + path.extname(req.file.originalname);\n+ const dest = path.resolve(uploadDir, safeName);\n+ if (!dest.startsWith(uploadDir)) throw new Error('Invalid path');"
                }
            ],
            "unit_tests": "describe('handleUpload security', () => {\n  it('rejects path traversal attempts', async () => {\n    const res = await request(app).post('/upload').send({ destination: '../../etc' });\n    expect(res.status).toBe(400);\n  });\n});",
            "verdict": "REQUEST_CHANGES"
        }
    },
    {
        "diff": """diff --git a/models/payment_processor.py b/models/payment_processor.py
index 99d81a..f8723c 100644
--- a/models/payment_processor.py
+++ b/models/payment_processor.py
@@ -40,6 +40,8 @@ def process_refund(order_id, amount_cents):
     order = get_order(order_id)
     if order.status != "COMPLETED":
         raise ValueError("Order not eligible for refund")
+    order.refunded_amount_cents += amount_cents
     gateway.refund_charge(order.charge_id, amount_cents)
-    order.refunded_amount_cents += amount_cents
+    db.commit()""",
        "review": {
            "summary": "Alters order state before executing external payment gateway refund.",
            "risk_level": "HIGH",
            "findings": [
                {
                    "file": "models/payment_processor.py",
                    "type": "BUG",
                    "title": "Uncaught Gateway Failure Causes Inconsistent State",
                    "description": "If gateway.refund_charge throws an exception or network error, order.refunded_amount_cents will have already been updated in memory and may leave records in an inconsistent state.",
                    "suggested_fix": "+ try:\n+     gateway.refund_charge(order.charge_id, amount_cents)\n+ except GatewayError as exc:\n+     logger.error(f'Refund failed: {exc}')\n+     raise\n+ order.refunded_amount_cents += amount_cents\n+ db.commit()"
                }
            ],
            "unit_tests": "def test_refund_failure_does_not_mutate_order(mocker):\n    mocker.patch('gateway.refund_charge', side_effect=GatewayError('Timeout'))\n    with pytest.raises(GatewayError):\n        process_refund('ord_123', 500)\n    assert get_order('ord_123').refunded_amount_cents == 0",
            "verdict": "REQUEST_CHANGES"
        }
    },
    {
        "diff": """diff --git a/utils/string_helpers.go b/utils/string_helpers.go
index 10a8fc..44e892 100644
--- a/utils/string_helpers.go
+++ b/utils/string_helpers.go
@@ -8,7 +8,9 @@ func ConcatTokens(tokens []string) string {
-    var res string
-    for _, t := range tokens {
-        res += t + ","
-    }
-    return strings.TrimSuffix(res, ",")
+    return strings.Join(tokens, ",")
 }""",
        "review": {
            "summary": "Replaced O(n^2) string concatenation loop with strings.Join in Go.",
            "risk_level": "LOW",
            "findings": [
                {
                    "file": "utils/string_helpers.go",
                    "type": "PERFORMANCE",
                    "title": "Optimized String Allocation",
                    "description": "Using strings.Join pre-allocates the buffer, avoiding multiple heap re-allocations on every loop iteration.",
                    "suggested_fix": "# Implementation is clean and optimal."
                }
            ],
            "unit_tests": "func TestConcatTokens(t *testing.T) {\n    tokens := []string{\"alpha\", \"beta\", \"gamma\"}\n    if got := ConcatTokens(tokens); got != \"alpha,beta,gamma\" {\n        t.Fatalf(\"expected alpha,beta,gamma, got %s\", got)\n    }\n}",
            "verdict": "APPROVE"
        }
    },
    {
        "diff": """diff --git a/worker/job_consumer.py b/worker/job_consumer.py
index ff412b..cc8891 100644
--- a/worker/job_consumer.py
+++ b/worker/job_consumer.py
@@ -34,6 +34,8 @@ def process_queue():
     while True:
         job = queue.pop()
         if not job:
-            time.sleep(1)
+            continue
         handle_job(job)""",
        "review": {
            "summary": "Removed sleep delay from polling loop when the job queue is empty.",
            "risk_level": "HIGH",
            "findings": [
                {
                    "file": "worker/job_consumer.py",
                    "type": "PERFORMANCE",
                    "title": "Busy-Waiting CPU Spike",
                    "description": "Removing the sleep creates an infinite busy-wait loop that will consume 100% CPU core usage when no jobs are present.",
                    "suggested_fix": "-            continue\n+            time.sleep(0.5)  # or use blocking queue pop with timeout"
                }
            ],
            "unit_tests": "def test_queue_empty_sleeps(mocker):\n    mock_sleep = mocker.patch('time.sleep')\n    mocker.patch('queue.pop', side_effect=[None, StopIteration])\n    try:\n        process_queue()\n    except StopIteration:\n        pass\n    assert mock_sleep.called",
            "verdict": "REQUEST_CHANGES"
        }
    },
    {
        "diff": """diff --git a/core/rate_limiter.py b/core/rate_limiter.py
index ab2381..7723fd 100644
--- a/core/rate_limiter.py
+++ b/core/rate_limiter.py
@@ -18,6 +18,12 @@ class TokenBucket:
     def allow_request(self, client_ip: str) -> bool:
         now = time.time()
+        # Clean up stale IP records older than 1 hour to prevent memory bloat
+        if len(self.records) > 10000:
+            cutoff = now - 3600
+            self.records = {ip: t for ip, t in self.records.items() if t > cutoff}
         last = self.records.get(client_ip, 0)
         if now - last < self.rate_limit_seconds:
             return False
         self.records[client_ip] = now
         return True""",
        "review": {
            "summary": "Added garbage collection mechanism to prune stale IP records from the in-memory token bucket rate limiter.",
            "risk_level": "LOW",
            "findings": [
                {
                    "file": "core/rate_limiter.py",
                    "type": "PERFORMANCE",
                    "title": "Stale Record Pruning",
                    "description": "Prevents unbounded memory growth in long-running services by sweeping inactive client records when dictionary exceeds 10,000 entries.",
                    "suggested_fix": "# Looks solid. For distributed environments, consider backing with Redis."
                }
            ],
            "unit_tests": "def test_pruning_cleans_old_ips():\n    limiter = TokenBucket(rate_limit_seconds=1)\n    limiter.records = {f'10.0.0.{i}': time.time() - 4000 for i in range(10001)}\n    limiter.allow_request('192.168.1.1')\n    assert len(limiter.records) <= 1",
            "verdict": "APPROVE"
        }
    },
    {
        "diff": """diff --git a/services/user_service.py b/services/user_service.py
index ba1230..49cc01 100644
--- a/services/user_service.py
+++ b/services/user_service.py
@@ -21,4 +21,6 @@ def update_user_profile(user_id, updates):
     user = db.users.find(user_id)
     if not user:
         raise NotFoundException()
+    for key, value in updates.items():
+        setattr(user, key, value)
     db.save(user)
     return user""",
        "review": {
            "summary": "Applies user-provided dictionary updates directly to user model attributes via setattr.",
            "risk_level": "HIGH",
            "findings": [
                {
                    "file": "services/user_service.py",
                    "type": "SECURITY",
                    "title": "Mass Assignment Vulnerability",
                    "description": "Directly mapping request payloads to model attributes allows malicious users to overwrite sensitive fields such as is_admin, role, balance, or password_hash.",
                    "suggested_fix": "+ ALLOWED_FIELDS = {'display_name', 'bio', 'avatar_url'}\n+ for key, value in updates.items():\n+     if key in ALLOWED_FIELDS:\n+         setattr(user, key, value)"
                }
            ],
            "unit_tests": "def test_mass_assignment_prevented():\n    user = User(id=1, is_admin=False)\n    with pytest.raises(SecurityError) or check_field:\n        update_user_profile(1, {'is_admin': True, 'display_name': 'Hacker'})\n    assert user.is_admin is False",
            "verdict": "REQUEST_CHANGES"
        }
    }
]

# Extended scenarios for fine-tuning dataset expansion (beyond the original 8 seeds).
# These cover additional vulnerability types, languages, and code patterns.
EXPANDED_SCENARIOS = [
    {
        "diff": """diff --git a/db/queries.py b/db/queries.py
index a1b2c3..d4e5f6 100644
--- a/db/queries.py
+++ b/db/queries.py
@@ -10,3 +10,4 @@ def find_user(id):
     query = "SELECT * FROM users WHERE id = "
+    query += id
     results = db.execute(query).fetchall()
     return results""",
        "review": {
            "summary": "Dynamic SQL query constructed through string concatenation.",
            "risk_level": "CRITICAL",
            "findings": [
                {
                    "file": "db/queries.py",
                    "type": "SECURITY",
                    "title": "SQL Injection via String Concatenation",
                    "description": "User input appended directly to SQL query string enables injection attacks. Use parameterized queries instead.",
                    "suggested_fix": "+    query = \"SELECT * FROM users WHERE id = %s\"\n+    query += id\n+    results = db.execute(query, (id,)).fetchall()"
                }
            ],
            "unit_tests": "def test_sql_injection_parametrized():\n    with pytest.raises(SecurityError):\n        find_user(\"1 OR 1=1\")"
        }
    },
    {
        "diff": """diff --git a/api/orders.py b/api/orders.py
index x9y8z7..w0v1u2 100644
--- a/api/orders.py
+++ b/api/orders.py
@@ -20,4 +20,5 @@ def process_order(items, total):
      if not items:
          raise ValueError("Empty cart")
+    assert total > 0, "Total must be positive"
     charge = stripe.Charge.create(amount=total, currency='usd')
     return charge.id""",
        "review": {
            "summary": "Added assertion to validate order total before charging.",
            "risk_level": "HIGH",
            "findings": [
                {
                    "file": "api/orders.py",
                    "type": "BUG",
                    "title": "Missing Input Validation Before Payment",
                    "description": "Assertion ensures total is positive before calling Stripe API, preventing zero/negative charges.",
                    "suggested_fix": "# Looks good. Also consider adding an upper bound check."
                }
            ],
            "unit_tests": "def test_order_total_validated():\n    with pytest.raises(ValueError):\n        process_order([], 0)"
        }
    },
    {
        "diff": """diff --git a/utils/format.py b/utils/format.py
index m1n2o3..p4q5r6 100644
--- a/utils/format.py
+++ b/utils/format.py
@@ -15,3 +15,4 @@ def format_name(name):
     return name.strip()
+    return name.title()""",
        "review": {
            "summary": "Added title-case formatting to name normalization.",
            "risk_level": "LOW",
            "findings": [
                {
                    "file": "utils/format.py",
                    "type": "STYLE",
                    "title": "Case Normalization Added",
                    "description": "The .title() method ensures consistent capitalization of user-provided names.",
                    "suggested_fix": "# Looks good. Consider edge cases with apostrophes or acronyms."
                }
            ],
            "unit_tests": "def test_name_title_case():\n    assert format_name('john doe') == 'John Doe'\n    assert format_name(o'connor) == \"O'Connor\""
        }
    },
    {
        "diff": """diff --git a/pkg/validator.go b/pkg/validator.go
index a1b2c3..d4e5f6 100644
--- a/pkg/validator.go
+++ b/pkg/validator.go
@@ -20,4 +20,7 @@ func ValidateEmail(email string) bool {
     if len(email) > 254 {
         return false
 }
+    if strings.Count(email, "@") != 1 {
+        return false
+    }
     return true""",
        "review": {
            "summary": "Added check for exactly one @ symbol in email validation.",
            "risk_level": "LOW",
            "findings": [
                {
                    "file": "pkg/validator.go",
                    "type": "CONFIGURATION",
                    "title": "Email Validation: Single @ Symbol",
                    "description": "Ensures the email contains exactly one @ symbol, a basic but important validity check.",
                    "suggested_fix": "# Looks good. Also consider using a regex for full RFC validation."
                }
            ],
            "unit_tests": "func TestValidateEmail(t *testing.T) {\n    assert ValidateEmail(\"test@example.com\") == true\n    assert ValidateEmail(\"invalid\") == false\n    assert ValidateEmail(\"two@@at\") == false"
        }
    },
    {
        "diff": """diff --git a/core/config.py b/core/config.py
index x1y2z3..a4b5c6 100644
--- a/core/config.py
+++ b/core/config.py
@@ -10,3 +10,4 @@ def load_config(path):
     config = {}
+    config['debug'] = True
     # Note: debug mode should not be enabled in production
     return config""",
        "review": {
            "summary": "Added debug flag to configuration loading.",
            "risk_level": "HIGH",
            "findings": [
                {
                    "file": "core/config.py",
                    "type": "CONFIGURATION",
                    "title": "Debug Mode Enabled in Configuration",
                    "description": "Setting debug=True in configuration can expose sensitive information and allow remote code execution in production environments.",
                    "suggested_fix": "+ import os\n+ config['debug'] = os.environ.get('FLASK_ENV', 'production') != 'production'"
                }
            ],
            "unit_tests": "def test_debug_not_in_production():\n    import os\n    os.environ['FLASK_ENV'] = 'production'\n    assert load_config('config.py')['debug'] == False"
        }
    },
    {
        "diff": """diff --git a/worker/processor.rs b/worker/processor.rs
index a1b2c3..d4e5f6 100644
--- a/worker/processor.rs
+++ b/worker/processor.rs
@@ -10,3 +10,4 @@ fn process_job(job: Job) {
     let result = job.data.parse::<Value>()?;
     // Missing error handling for malformed JSON
     let output = result.get("output").and_then(|v| v.as_str());
     println!("{}", output)""",
        "review": {
            "summary": "Missing error handling for JSON parsing result.",
            "risk_level": "MEDIUM",
            "findings": [
                {
                    "file": "worker/processor.rs",
                    "type": "BUG",
                    "title": "Unwrap Without Error Check",
                    "description": "Using .and_then() without checking the Result type can panic on malformed input data.",
                    "suggested_fix": "+ match result {\n    Ok(v) => { let output = v.get(\"output\").and_then(|v2| v2.as_str()); \n    println!(\"{}\", output);\n    Ok(())\n    Err(e) => { eprintln!(\"Parse error: {:?}\", e);\n    Err(e)\n    }"
                }
            ],
            "unit_tests": "fn test_json_error_handling() {\n    let bad = r#\"not json\"#;\n    let result: Result<Value, _> = bad.parse();\n    assert!(result.is_err());"
        }
    },
    {
        "diff": """diff --git a/api/search.ts b/api/search.ts
index a1b2c3..d4e5f6 100644
--- a/api/search.ts
+++ b/api/search.ts
@@ -15,4 +15,5 @@ function searchProducts(query) {
     const results = await db.query("SELECT * FROM products WHERE name LIKE ")
+    const likeQuery = `%${query}%`;
     const results = await db.query(likeQuery);
     return results""",
        "review": {
            "summary": "Dynamic LIKE query constructed with string interpolation.",
            "risk_level": "CRITICAL",
            "findings": [
                {
                    "file": "api/search.ts",
                    "type": "SECURITY",
                    "title": "SQL Injection in LIKE Query",
                    "description": "User-controlled search query interpolated directly into SQL LIKE clause enables injection. Use parameterized queries with escape handling.",
                    "suggested_fix": "+    const likePattern = '%?%'.replace('?', query);\n+    const results = await db.query(\"SELECT * FROM products WHERE name LIKE $1\", [likePattern]);"
                }
            ],
            "unit_tests": "it('escapes like query parameters', async () => {\n    const res = await request(app).post('/search').send({ query: \"' OR '1'='1\" });\n    expect(res.status).toBe(400);\n});"
        }
    }
]

def _reference_report(item: Dict[str, Any], scenario_number: int) -> ReviewReport:
    """Convert legacy seed annotations into the production v2 contract.

    The conversion intentionally withholds legacy replacement snippets: they are not
    full, context-validated unified patches and must not train the model to call
    suggestions applied or verified.
    """
    annotation = item["review"]
    parsed = parse_unified_diff(item["diff"])
    paths = [changed.new_path for changed in parsed if changed.new_path]
    findings = []
    tests = []

    # Approved seeds are negative examples. Historical notes such as "looks good"
    # are not production findings.
    if annotation["verdict"] != "APPROVE":
        for index, legacy in enumerate(annotation.get("findings", []), 1):
            path = legacy["file"]
            changed = next((entry for entry in parsed if entry.new_path == path), None)
            evidence_line = next((line for line in (changed.added_lines if changed else []) if line.new_line), None)
            if evidence_line is None:
                raise ValueError(f"Seed {scenario_number} has no added source location for {path}")
            category = legacy.get("type", "BUG")
            if category not in {"SECURITY", "BUG", "PERFORMANCE", "STYLE", "MAINTAINABILITY", "CONFIGURATION"}:
                category = "BUG"
            severity = annotation["risk_level"]
            test = UnitTestFixture(
                name=f"generated_seed_{scenario_number}_{index}",
                framework="pytest" if path.endswith(".py") else "project-specific",
                description="Synthetic training candidate. It has not been executed.",
                code=annotation.get("unit_tests", ""),
                status="GENERATED",
            )
            tests.append(test)
            findings.append(Finding(
                id=f"TRAIN-{scenario_number:03d}-{index:02d}",
                rule_id=f"TRAIN-{category}-{scenario_number:03d}",
                title=legacy["title"],
                category=category,
                severity=severity,
                confidence="MEDIUM",
                file=path,
                line_start=evidence_line.new_line,
                line_end=evidence_line.new_line,
                evidence=[evidence_line.text],
                description=legacy["description"],
                exploit_conditions=None,
                remediation=(
                    "Review the affected API and surrounding call sites before implementing a context-validated fix. "
                    "This synthetic seed does not provide a verified patch."
                ),
                suggested_fix=None,
                patch_status="SUGGESTION_ONLY",
                provenance="LOCAL_LLM",
                related_tests=[test],
            ))

    counts = SeverityCounts(
        critical=sum(finding.severity == "CRITICAL" for finding in findings),
        high=sum(finding.severity == "HIGH" for finding in findings),
        medium=sum(finding.severity == "MEDIUM" for finding in findings),
        low=sum(finding.severity == "LOW" for finding in findings),
    )
    verdict = annotation["verdict"]
    summary = annotation["summary"]
    if not findings and verdict == "APPROVE":
        summary = f"{summary} No finding is reported for this clean training example."
    return ReviewReport(
        summary=summary,
        risk_level=annotation["risk_level"],
        verdict=verdict,
        counts=counts,
        findings=findings,
        unit_tests=tests,
        execution_time_ms=0,
        analyzed_files=paths,
        engine="CodeGuardian training reference",
        analyzers=["Synthetic seed annotation"],
        timestamp="2026-01-01T00:00:00+00:00",
    )


def format_chatml(diff: str, review: Dict[str, Any]) -> Dict[str, Any]:
    """Format single sample into Qwen ChatML conversational structure."""
    return {
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT
            },
            {
                "role": "user",
                "content": f"Please review the following git diff and output your review in structured JSON:\n\n```diff\n{diff}\n```"
            },
            {
                "role": "assistant",
                "content": json.dumps(review, indent=2)
            }
        ]
    }

def generate_dataset(output_dir: str = "data", total_samples: int = 8, train_ratio: float = 0.75):
    """Generate a leakage-free synthetic seed split and its provenance manifest.

    Exact template duplication is deliberately rejected. Additional training data
    should come from independently licensed, provenance-tracked sources rather than
    repeating the small built-in scenario set.
    """
    os.makedirs(output_dir, exist_ok=True)
    if total_samples > len(SCENARIOS):
        raise ValueError(
            f"Only {len(SCENARIOS)} independent built-in seeds are available. "
            "Refusing to duplicate templates across a training split."
        )
    if total_samples < 2:
        raise ValueError("At least two independent samples are required for train/validation separation.")

    selected = list(enumerate(SCENARIOS[:total_samples], 1))
    random.Random(42).shuffle(selected)
    split_idx = max(1, min(len(selected) - 1, round(len(selected) * train_ratio)))
    train_records = selected[:split_idx]
    val_records = selected[split_idx:]
    train_samples = [format_chatml(item["diff"], _reference_report(item, number).model_dump()) for number, item in train_records]
    val_samples = [format_chatml(item["diff"], _reference_report(item, number).model_dump()) for number, item in val_records]

    train_path = os.path.join(output_dir, "sample_train.jsonl")
    val_path = os.path.join(output_dir, "sample_val.jsonl")

    with open(train_path, "w", encoding="utf-8") as f:
        for s in train_samples:
            f.write(json.dumps(s) + "\n")

    with open(val_path, "w", encoding="utf-8") as f:
        for s in val_samples:
            f.write(json.dumps(s) + "\n")

    manifest_path = os.path.join(output_dir, "dataset_provenance.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump({
            "schema_version": "2.0.0",
            "source": "CodeGuardian built-in synthetic seed scenarios",
            "license": "Project-authored examples; not a security benchmark",
            "train_scenario_ids": [number for number, _ in train_records],
            "validation_scenario_ids": [number for number, _ in val_records],
            "final_evaluation": "Not included. Maintain an independent, untouched evaluation set.",
            "notes": "No scenario template is duplicated across the train/validation split.",
        }, f, indent=2)

    print(f"Generated {len(train_samples)} training samples -> {train_path}")
    print(f"Generated {len(val_samples)} validation samples -> {val_path}")
    print(f"Wrote provenance manifest -> {manifest_path}")

if __name__ == "__main__":
    generate_dataset()

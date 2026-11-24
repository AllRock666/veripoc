# Autonomous PoC Verifier

An empirical, defensive false-positive eliminator for Application Security (AppSec) scanners.

The pipeline ingests alerts from automated DAST/SAST scanners (**OWASP ZAP**, **Nuclei**, **Semgrep SARIF**), directs a Large Language Model (LLM) to synthesize minimal, benign verification scripts adhering to strict telemetry contracts, executes them inside isolated ephemeral Docker sandbox containers against intentionally vulnerable lab applications (**OWASP Juice Shop**, **DVWA**), and relies on **deterministic code oracles** (never the LLM) to decide ground-truth verdicts: `CONFIRMED`, `FALSE_POSITIVE`, or `INCONCLUSIVE`.

---

## Architecture Overview

```
 [OWASP ZAP]    [Nuclei]    [Semgrep SARIF]
      │             │              │
      └─────────────┼──────────────┘
                    ▼
         Ingestion & Deduplication (path, param, CWE)
                    ▼
          Strategy Engine (LLM)
       ┌────────────┴────────────┐
       ▼                         ▼
HTTP Requests Script       Playwright Headless Script
(SQLi / SSRF / IDOR)               (XSS)
       │                         │
       └────────────┬────────────┘
                    ▼
       Ephemeral Docker Sandbox
   (read-only FS, cap_drop ALL, internal lab_net)
                    ▼
       Lab Targets (Juice Shop / DVWA / Canary)
                    ▼
       Telemetry JSON Line Output
                    ▼
        Deterministic Code Oracles
   (Timing Delta / Canary Match / OOB Callback / JS Exec)
                    │
   ┌────────────────┼────────────────┐
   ▼                ▼                ▼
CONFIRMED     FALSE_POSITIVE    INCONCLUSIVE (Taxonomy)
```

---

## Quick Start & Setup

### 1. Prerequisites
- Python 3.10+
- Docker & Docker Compose
- Ollama (e.g. `ollama pull qwen2.5-coder:7b`) or any OpenAI-compatible API endpoint

### 2. Install Dependencies
```bash
pip install -r requirements.txt
pytest
```

### 3. Build Sandbox Runner Images
The system uses a two-tier sandbox architecture to keep containers minimal while supporting browser-based execution:
```bash
# 1. Standard runner (Python stdlib + requests) for SQLi, SSRF, IDOR
docker build -t poc-runner:latest sandbox_image/

# 2. Browser runner (Playwright + headless Chromium) for XSS
docker build -t poc-runner-browser:latest -f sandbox_image/Dockerfile.browser sandbox_image/
```

### 4. Start Isolated Lab Targets
```bash
docker compose -f lab/docker-compose.yml up -d --build
```
The lab starts:
- `juiceshop`: OWASP Juice Shop on `lab_net` (published on host port `3000` for scanners).
- `dvwa`: Damn Vulnerable Web Application on `lab_net` (published on host port `4280`).
- `canary`: Out-of-band callback listener on `lab_net` (admin port `9999` published on host for ground truth retrieval).

### 5. Seed Lab Ground Truth
Seed User A, User B, and the User B canary records (addresses and basket items) in Juice Shop so IDOR and SQLi canary extraction have verifiable ground truth:
```bash
python lab/seed.py --target http://localhost:3000 --canary CANARY_JuiceShop_UserB_Secret_Record_83f9 --out lab/seeds.json
```

---

## Running Experiments & Workflow

### Step 1: Ingest Scanner Alerts
Normalize and deduplicate reports from OWASP ZAP, Nuclei, or Semgrep SARIF into a unified format:
```bash
python cli.py ingest \
  --zap zap_report.json \
  --nuclei nuclei.jsonl \
  --semgrep semgrep.sarif \
  --out findings.json
```

### Step 2: Run Verification (Configuration C)
Run the autonomous verification loop against the lab:
```bash
python cli.py verify \
  --findings findings.json \
  --target http://juiceshop:3000 \
  --model qwen2.5-coder:7b \
  --base-url http://localhost:11434/v1 \
  --canary-value CANARY_JuiceShop_UserB_Secret_Record_83f9 \
  --results results.json
```

### Step 3: Evaluate & Export Metrics
Evaluate precision, recall, and false-positive reduction rate (FPRR %) against ground truth, and export CSV and charts:
```bash
python cli.py report \
  --results results.json \
  --truth lab/ground_truth.json \
  --csv-out results.csv \
  --charts-out results/
```

### Step 4: Run the Complete Ablation Benchmark
To reproduce thesis experiments across all configurations in a single run:
```bash
python cli.py benchmark \
  --findings findings.json \
  --truth lab/ground_truth.json \
  --target http://juiceshop:3000 \
  --model qwen2.5-coder:7b \
  --canary-value CANARY_JuiceShop_UserB_Secret_Record_83f9 \
  --out-dir results/
```

This benchmark executes and compares:
- **Configuration A (Raw Scanner)**: Baseline trusting all scanner alerts.
- **Configuration B (LLM-Only Zero-Shot)**: Direct LLM triage of alert evidence without sandbox execution.
- **Configuration C (Autonomous PoC Verifier)**: Full closed-loop verification (LLM + sandbox + deterministic oracles).

Generated artifacts in `results/`:
- `benchmark_metrics.json`: Precision, Recall, F1, and FPRR (%) across configurations.
- `findings_summary.csv`: Tabular per-finding record with endpoint, parameter, CWE, verdict, reason, duration, tokens, failure mode, and ground truth.
- `precision_recall_fprr.png`: Publication-grade comparative bar chart.
- `cost_vs_latency.png`: Per-finding token cost vs. wall-clock latency scatter plot.
- `failure_taxonomy.png`: Frequency breakdown of INCONCLUSIVE failure modes.

---

## INCONCLUSIVE Failure-Mode Taxonomy

When verification cannot reach a decisive `CONFIRMED` or `FALSE_POSITIVE` verdict within `max_attempts`, the attempt history is categorized into a failure taxonomy:

| Failure Mode | Definition & Trigger Conditions |
|---|---|
| `auth_expiry` | Target returned HTTP 401/403, JWT expiration, or session invalidation during verification. |
| `syntax_error` | LLM-generated script crashed with `SyntaxError`, `IndentationError`, `NameError`, or missing module imports. |
| `timeout` | Container exceeded execution ceiling (default: 30 seconds) and was terminated by the watchdog. |
| `no_telemetry` | Script exited cleanly (exit code 0) but failed to print a valid JSON object matching the telemetry contract. |
| `other` | Abnormal container exit (e.g., OOM kill, non-zero exit without captured Python traceback). |

---

## Sandbox Threat Model & Security Controls

Because the verification engine executes untrusted code synthesized by an LLM that ingests external scanner data, the sandbox architecture is designed under an adversarial threat model.

### 1. Attacker Model & Threat Vectors
- **Indirect Prompt Injection**: Scanner evidence (e.g. reflected HTTP headers, parameter values, page body snippets) could contain malicious instructions attempting to hijack the code generator.
- **Data Exfiltration**: Generated scripts attempting to transmit internal lab tokens or host environment variables to external servers.
- **Host Breakout & Lateral Movement**: Generated scripts attempting container escape, kernel privilege escalation, or pivoting to unapproved internal subnets.
- **Denial of Service**: Infinite loops, fork bombs, memory consumption bombs, or disk exhaustion.
- **Evasion & Fabricated Verdicts**: Generated scripts attempting to spoof telemetry to deceive the oracle.

### 2. Defense-in-Depth Mitigations

| Layer | Security Control | Implementation Mechanism |
|---|---|---|
| **Network Isolation** | Zero Internet Egress for Runners | Runner containers run exclusively on Docker network `lab_net` defined with `internal: true` with zero internet egress. Lab targets (`juiceshop`, `dvwa`, `canary`) are bridged to both `lab_net` and the Docker `default` network to allow host scanner access (e.g. ZAP, Nuclei) and dependency retrieval; sandbox runner containers are strictly constrained to `lab_net` with no internet route. |
| **Filesystem Immutability** | Read-Only Root Filesystem | Container started with `read_only=True`. The test script volume is mounted `mode="ro"`. |
| **Volatile Ephemeral Storage** | Memory-backed tmpfs | Writable filesystem access is constrained to an in-memory `tmpfs` (`/tmp:size=16m` for standard, `size=64m` for browser). All written artifacts disappear when the container exits. |
| **Privilege Deprivation** | Capability Dropping & Non-Root Execution | Containers drop all Linux capabilities (`cap_drop=["ALL"]`) and enforce `security_opt=["no-new-privileges"]`. Execution runs under unprivileged users (`runner` or `pwuser`). |
| **Resource Quotas** | Strict Resource Ceilings | Containers enforce `mem_limit="256m"` (standard) / `"512m"` (browser), CPU limits `0.5` (standard) / `1.0` (browser), and `pids_limit=64` (standard) / `256` (browser, preventing fork bombs while allowing Chromium threads). |
| **Execution Watchdog** | Hard Timeout Ceiling | Container wait has a 30-second watchdog. On timeout, the container is killed (`SIGKILL`) and pruned immediately. |
| **Oracle Decoupling** | Deterministic Code Evaluation | The LLM is **never** permitted to evaluate whether the exploit succeeded. Code oracles verify empirical side-effects (timing variance across trials, seeded canary extraction, out-of-band listener callbacks, and headless browser DOM event triggers). |

---

## Unit Testing

Run the test suite across all modules (parsers, oracles, strategy, orchestrator, seed, taxonomy, reporting, CLI benchmark):
```bash
pytest
```
All tests execute locally using in-memory databases and mocked services without requiring Docker or active LLM endpoints.

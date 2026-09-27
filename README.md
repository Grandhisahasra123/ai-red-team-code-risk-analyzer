# 🔴 AI Red Team – Code Risk Analyzer

> **Hackathon MVP** — a controlled, browser-based tool that demonstrates the concept of AI-driven adversarial testing on vulnerable code snippets.

---

## Problem

AI-generated code can contain subtle security vulnerabilities that are hard to spot in code review.
Traditional static analysis tools flag patterns but rarely *show* what an attack looks like or what evidence it leaves behind.

## Solution

A lightweight Streamlit app that:

1. Presents intentionally vulnerable Python code examples.
2. Generates (or selects) adversarial attack inputs for each vulnerability.
3. Runs **controlled, safe** tests to observe how the code reacts.
4. Displays concrete before/after evidence so the risk becomes tangible.

## How It Works

```
Select demo → view vulnerable code
    → generate attack cases (LLM or predefined)
        → run controlled tests (no arbitrary code execution)
            → compare expected vs. observed behaviour
                → show evidence + risk rating
```

The app **never executes user-pasted code**. All tests run against predefined internal functions.

---

## Features

| Feature | Details |
|---|---|
| 3 built-in demo vulnerabilities | eval injection, SQL injection, missing input validation |
| Adversarial attack generator | Predefined (demo mode) or LLM-generated (with API key) |
| Controlled test runner | Safe simulated execution, no shell access |
| Evidence cards | Expected vs. observed behaviour, per-attack detail |
| Risk explanations | Plain-English description + recommended fix |
| LLM fallback | Works 100% without an API key |

---

## Tech Stack

- **Python 3.10+**
- **Streamlit** – web UI
- **OpenAI Python SDK** – optional, for LLM-generated attacks

---

## How to Run

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Run the app

```bash
streamlit run app.py
```

The app opens automatically at **http://localhost:8501**

### 3. (Optional) Enable LLM mode

```bash
# macOS / Linux
export OPENAI_API_KEY=sk-...

# Windows PowerShell
$env:OPENAI_API_KEY="sk-..."

streamlit run app.py
```

---

## Demo Walkthrough

1. Open the app in your browser.
2. Select **"1 · Unsafe eval / Code Execution"** from the dropdown.
3. Read the vulnerable code snippet and description.
4. Click **⚡ Analyze Code**.
5. Observe:
   - The attack cases table (which attacks succeeded).
   - The detailed evidence cards (expected vs. observed behaviour).
   - The risk explanation and recommended fix.
6. Repeat with the SQL injection and input validation demos.

---

## Limitations

- This is a **demo/prototype**, not a production security scanner.
- Only Python is supported.
- Attack cases are predefined (or LLM-generated for the 3 built-in demos).
- No arbitrary user code is executed – by design.

---

## Future Improvements

- Upload arbitrary code and use an LLM to auto-detect vulnerabilities.
- Expand to more vulnerability categories (path traversal, SSRF, insecure deserialization).
- Add a scoring / severity rating system.
- Export results as a PDF report.
- Support additional languages (JavaScript, Go).

---

## Disclaimer

This is a hackathon prototype for controlled, simulated testing and is **not** a production security scanner. No user-submitted code is executed at runtime.

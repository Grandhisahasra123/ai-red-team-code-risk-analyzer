"""
AI Red Team – Code Risk Analyzer
Hackathon MVP: controlled vulnerability demonstration tool.
"""

import streamlit as st
import os

# ── Optional LLM support (graceful fallback if no key) ─────────────────────
def try_llm_analysis(code: str, vuln_type: str) -> dict | None:
    """Try to use OpenAI if OPENAI_API_KEY is set; return None otherwise."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        return None
    try:
        from openai import OpenAI  # type: ignore
        client = OpenAI(api_key=api_key)
        prompt = f"""You are a security red-team assistant.
Given this Python code snippet and its known vulnerability type ({vuln_type}),
generate exactly 2 adversarial attack inputs and explain each one.

Code:
{code}

Reply in this exact JSON format (no markdown fences):
{{
  "attacks": [
    {{"input": "<attack string>", "explanation": "<why this is dangerous>"}},
    {{"input": "<attack string>", "explanation": "<why this is dangerous>"}}
  ],
  "risk_summary": "<one sentence summary of the risk>"
}}"""
        resp = client.chat.completions.create(
            model="gpt-3.5-turbo",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=400,
        )
        import json
        return json.loads(resp.choices[0].message.content)
    except Exception:
        return None


# ── Demo definitions ────────────────────────────────────────────────────────

DEMOS = {
    "1 · Unsafe eval / Code Execution": {
        "description": "Uses Python's `eval()` to process user input, allowing arbitrary expression evaluation.",
        "code": '''\
def calculate(user_input):
    """Evaluates a math expression from the user."""
    result = eval(user_input)   # ← UNSAFE: executes anything
    return result
''',
        "vuln_type": "Unsafe eval / Code Execution",
        "attacks": [
            {
                "input": "__import__('os').getcwd()",
                "label": "Directory disclosure",
            },
            {
                "input": "__import__('os').listdir('.')",
                "label": "Directory listing",
            },
            {
                "input": "[x for x in ().__class__.__bases__[0].__subclasses__() if 'warning' in x.__name__.lower()]",
                "label": "Subclass introspection",
            },
        ],
        "run_test": "eval_test",
    },

    "2 · SQL Injection – Vulnerable Query Builder": {
        "description": "Builds a SQL query by string concatenation, making it trivially injectable.",
        "code": '''\
def get_user(username):
    """Fetch a user record by username."""
    query = "SELECT * FROM users WHERE username = \'" + username + "\'"
    return query   # ← In a real app this would be executed against a DB
''',
        "vuln_type": "SQL Injection",
        "attacks": [
            {
                "input": "' OR '1'='1",
                "label": "Auth bypass – always-true condition",
            },
            {
                "input": "admin'--",
                "label": "Comment injection – truncates query",
            },
            {
                "input": "'; DROP TABLE users;--",
                "label": "Destructive injection",
            },
        ],
        "run_test": "sql_test",
    },

    "3 · Missing Input Validation": {
        "description": "Accepts numeric input without any bounds or type checking, causing unexpected behavior.",
        "code": '''\
def set_age(age_input):
    """Store a user\'s age after converting from string."""
    age = int(age_input)          # ← No validation at all
    discount = 100 / (18 - age)   # ← Division by zero if age == 18
    return {"age": age, "discount_factor": discount}
''',
        "vuln_type": "Missing Input Validation",
        "attacks": [
            {
                "input": "18",
                "label": "Division by zero",
            },
            {
                "input": "-999999",
                "label": "Extreme negative value",
            },
            {
                "input": "abc",
                "label": "Type confusion – non-numeric string",
            },
        ],
        "run_test": "validation_test",
    },
}


# ── Controlled test runners (NEVER execute user-pasted code) ────────────────

def run_eval_test(attack: dict) -> dict:
    """Safely demonstrate eval() risk without executing real attacks."""
    inp = attack["input"]
    # We only demonstrate with a safe subset; we do NOT call eval() on the input.
    safe_expressions = {"1+1", "2*3", "10-4"}
    if inp in safe_expressions:
        observed = str(eval(inp))  # noqa: S307  – only our own safe strings
        attacked = False
        evidence = "Input was a plain arithmetic expression – no injection detected."
    else:
        # Simulate what WOULD happen if eval() were called
        observed = f"[SIMULATED] eval() would execute: {inp!r}"
        attacked = True
        evidence = (
            f"The expression {inp!r} is not plain data. "
            "If passed to eval(), Python would execute it as code, "
            "potentially leaking information or causing harm."
        )
    return {
        "expected": "Input should be treated as data, not code.",
        "observed": observed,
        "attacked": attacked,
        "evidence": evidence,
    }


def run_sql_test(attack: dict) -> dict:
    """Build the vulnerable query and show how the input mutates it."""
    inp = attack["input"]
    safe_pattern_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
    # Build the query exactly as the vulnerable function would
    query = "SELECT * FROM users WHERE username = '" + inp + "'"
    attacked = any(c not in safe_pattern_chars for c in inp)
    if attacked:
        evidence = (
            f"The resulting query is:\n\n  {query}\n\n"
            "Special characters in the input break out of the string literal and alter "
            "the query's logic. A parameterised query would prevent this entirely."
        )
        observed = f"Mutated query: {query}"
    else:
        evidence = "Input contained only safe alphanumeric characters – query structure unchanged."
        observed = f"Safe query: {query}"
    return {
        "expected": "Query should only look up the exact username provided.",
        "observed": observed,
        "attacked": attacked,
        "evidence": evidence,
    }


def run_validation_test(attack: dict) -> dict:
    """Run the vulnerable function with the attack input and capture any exception."""
    inp = attack["input"]
    try:
        age = int(inp)
        discount = 100 / (18 - age)
        observed = f"age={age}, discount_factor={discount:.4f}"
        attacked = False
        evidence = "Input processed without error – no issue triggered by this input."
    except ZeroDivisionError:
        observed = "ZeroDivisionError: division by zero"
        attacked = True
        evidence = (
            f"age={inp} causes a division by zero in `100 / (18 - age)`. "
            "The application crashes. Input should be validated before arithmetic."
        )
    except ValueError:
        observed = f"ValueError: invalid literal for int() with base 10: {inp!r}"
        attacked = True
        evidence = (
            f"The value {inp!r} cannot be converted to an integer. "
            "No type check exists, so the app raises an unhandled exception."
        )
    return {
        "expected": "Function should validate input and return a safe result.",
        "observed": observed,
        "attacked": attacked,
        "evidence": evidence,
    }


TEST_RUNNERS = {
    "eval_test": run_eval_test,
    "sql_test": run_sql_test,
    "validation_test": run_validation_test,
}


# ── Streamlit UI ────────────────────────────────────────────────────────────

st.set_page_config(page_title="AI Red Team – Code Risk Analyzer", page_icon="🔴", layout="wide")

st.title("🔴 AI Red Team – Code Risk Analyzer")
st.markdown(
    "**Concept:** AI-generated or user-provided code → adversarial attack cases → "
    "controlled testing → detect suspicious behaviour → show concrete evidence."
)
st.divider()

# ── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")
    use_llm = bool(os.environ.get("OPENAI_API_KEY"))
    if use_llm:
        st.success("✅ OpenAI key detected – LLM mode active")
    else:
        st.info("ℹ️ No API key found – running in demo mode")
    st.markdown("---")
    st.markdown(
        "**Demo mode** uses predefined attack cases and safe simulated tests.\n\n"
        "Set `OPENAI_API_KEY` in your environment to enable LLM-generated attacks."
    )
    st.markdown("---")
    st.caption("🔬 Hackathon prototype – not a production scanner.")

# ── Demo selector ────────────────────────────────────────────────────────────
col1, col2 = st.columns([1, 2])

with col1:
    st.subheader("1 · Select a Demo")
    demo_choice = st.selectbox(
        "Choose a vulnerable code example:",
        list(DEMOS.keys()),
        label_visibility="collapsed",
    )

demo = DEMOS[demo_choice or list(DEMOS.keys())[0]]

with col2:
    st.subheader("2 · Code Under Test")
    st.markdown(f"**Vulnerability type:** `{demo['vuln_type']}`")
    st.markdown(f"_{demo['description']}_")
    st.code(demo["code"], language="python")

st.divider()

# ── Analyze button ───────────────────────────────────────────────────────────
st.subheader("3 · Run Analysis")

if st.button("⚡ Analyze Code", type="primary", use_container_width=True):

    # ── Step 1: LLM or fallback attacks ────────────────────────────────────
    with st.spinner("Generating attack cases…"):
        llm_result = try_llm_analysis(demo["code"], demo["vuln_type"]) if use_llm else None
        using_llm = llm_result is not None

    if using_llm:
        attack_list = [
            {"input": a["input"], "label": a["explanation"]}
            for a in llm_result["attacks"]
        ]
        risk_summary = llm_result.get("risk_summary", "")
        mode_badge = "🤖 LLM-generated attacks"
    else:
        attack_list = demo["attacks"]
        risk_summary = ""
        mode_badge = "📋 Demo mode – predefined attacks"

    st.caption(mode_badge)

    # ── Step 2: Run controlled tests ────────────────────────────────────────
    runner = TEST_RUNNERS[demo["run_test"]]
    results = []
    for attack in attack_list:
        res = runner(attack)
        results.append({**attack, **res})

    # ── Step 3: Render results ──────────────────────────────────────────────
    any_attacked = any(r["attacked"] for r in results)

    st.divider()
    if any_attacked:
        st.error("🚨 Potential vulnerability detected in this code!")
    else:
        st.success("✅ No issue detected in these tests.")

    st.markdown(f"### Vulnerability: `{demo['vuln_type']}`")
    if risk_summary:
        st.info(f"**Risk summary (LLM):** {risk_summary}")

    # ── Attack Cases table ──────────────────────────────────────────────────
    st.markdown("#### 🗡️ Attack Cases")
    header_cols = st.columns([2, 3, 1])
    header_cols[0].markdown("**Attack Input**")
    header_cols[1].markdown("**Label / Description**")
    header_cols[2].markdown("**Succeeded?**")
    st.markdown("---")
    for r in results:
        row = st.columns([2, 3, 1])
        row[0].code(r["input"], language="python")
        row[1].markdown(r["label"])
        row[2].markdown("🔴 Yes" if r["attacked"] else "🟢 No")

    # ── Detailed evidence cards ─────────────────────────────────────────────
    st.markdown("#### 🔍 Detailed Evidence")
    for i, r in enumerate(results, 1):
        status = "🔴 Attack succeeded" if r["attacked"] else "🟢 No issue"
        with st.expander(f"Test {i}: `{r['input']}` — {status}", expanded=r["attacked"]):
            detail_cols = st.columns(2)
            with detail_cols[0]:
                st.markdown("**Expected behaviour**")
                st.info(r["expected"])
                st.markdown("**Observed behaviour**")
                if r["attacked"]:
                    st.warning(r["observed"])
                else:
                    st.success(r["observed"])
            with detail_cols[1]:
                st.markdown("**Evidence**")
                st.markdown(r["evidence"])

    # ── Risk explanation ────────────────────────────────────────────────────
    st.markdown("#### ⚠️ Risk Explanation")
    explanations = {
        "Unsafe eval / Code Execution": (
            "Calling `eval()` on user input allows an attacker to execute arbitrary Python code "
            "within the application's process. This can lead to data exfiltration, file system access, "
            "or complete system compromise. **Fix:** never call `eval()` on untrusted input; "
            "use `ast.literal_eval()` for safe literal parsing or a dedicated expression parser."
        ),
        "SQL Injection": (
            "Building SQL queries by string concatenation allows an attacker to inject SQL syntax "
            "that changes the query's logic – bypassing authentication, extracting all rows, or "
            "destroying data. **Fix:** always use parameterised queries / prepared statements."
        ),
        "Missing Input Validation": (
            "Accepting raw input without type, range, or format checks leads to crashes "
            "(unhandled exceptions), logic errors, or exploitable states. "
            "**Fix:** validate and sanitise every input before use; handle exceptions explicitly."
        ),
    }
    st.markdown(explanations.get(demo["vuln_type"], "Review the evidence above for details."))

st.divider()

# ── Disclaimer ───────────────────────────────────────────────────────────────
st.caption(
    "⚠️ **Disclaimer:** This is a hackathon prototype for controlled, simulated testing "
    "and is **not** a production security scanner. No arbitrary user code is executed. "
    "All tests run against predefined safe demo functions only."
)

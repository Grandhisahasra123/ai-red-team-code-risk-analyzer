"""Quick smoke-test for the app logic (no Streamlit needed)."""
import sys, types

# ── Mock streamlit ──────────────────────────────────────────────────────────
st_mock = types.ModuleType("streamlit")

class FakeCtx:
    def __enter__(self): return self
    def __exit__(self, *a): pass
    def markdown(self, *a, **kw): pass
    def code(self, *a, **kw): pass
    def info(self, *a, **kw): pass
    def success(self, *a, **kw): pass
    def warning(self, *a, **kw): pass
    def caption(self, *a, **kw): pass
    def header(self, *a, **kw): pass

def fake_cols(spec):
    n = spec if isinstance(spec, int) else len(spec)
    return [FakeCtx() for _ in range(n)]

for attr in ["set_page_config","title","markdown","divider","subheader","selectbox",
             "code","button","spinner","caption","error","success","info","warning",
             "text_input","header"]:
    setattr(st_mock, attr, lambda *a, **kw: None)

st_mock.columns = fake_cols
st_mock.expander = lambda *a, **kw: FakeCtx()
st_mock.sidebar = FakeCtx()
sys.modules["streamlit"] = st_mock

# ── Import app ──────────────────────────────────────────────────────────────
import importlib.util
spec = importlib.util.spec_from_file_location("app", "app.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

run_eval_test = mod.run_eval_test
run_sql_test = mod.run_sql_test
run_validation_test = mod.run_validation_test

# ── Tests ───────────────────────────────────────────────────────────────────
failures = []

def check(name, result, expect_attacked):
    attacked = result["attacked"]
    status = "PASS" if attacked == expect_attacked else "FAIL"
    if status == "FAIL":
        failures.append(name)
    print(f"[{status}] {name}: attacked={attacked}")
    print(f"       observed: {result['observed'][:70]}")

# eval
check("eval – os.getcwd injection",
      run_eval_test({"input": "__import__('os').getcwd()", "label": "test"}),
      expect_attacked=True)
check("eval – safe arithmetic",
      run_eval_test({"input": "1+1", "label": "safe"}),
      expect_attacked=False)

# sql
check("sql – OR-always-true",
      run_sql_test({"input": "' OR '1'='1", "label": "inject"}),
      expect_attacked=True)
check("sql – DROP TABLE",
      run_sql_test({"input": "'; DROP TABLE users;--", "label": "drop"}),
      expect_attacked=True)
check("sql – safe username",
      run_sql_test({"input": "alice", "label": "safe"}),
      expect_attacked=False)

# validation
check("val – division by zero (age=18)",
      run_validation_test({"input": "18", "label": "zero-div"}),
      expect_attacked=True)
check("val – non-numeric input",
      run_validation_test({"input": "abc", "label": "type-error"}),
      expect_attacked=True)
check("val – safe age",
      run_validation_test({"input": "25", "label": "safe"}),
      expect_attacked=False)

print()
if failures:
    print(f"FAILURES: {failures}")
    sys.exit(1)
else:
    print("All tests passed!")

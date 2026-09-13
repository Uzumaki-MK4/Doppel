"""APIGuard Streamlit dashboard (BRAIN.md D28).

A thin consumer of the engine (invariant 1): it presents the SAVED artifacts —
the per-arm result JSONs, the ground truth, and the HTML report — so the whole
demo runs offline (wifi off). It never scans a live target: everything here is
read from `benchmark/results/*.json` and `benchmark/ground_truth.yaml`, which are
the canonical, committed measurements.

Run:  streamlit run dashboard.py

All Streamlit calls live inside `main()`; the data-prep helpers above it are pure
(no `st.`) so they can be unit-tested without the Streamlit runtime.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

from apiguard.core.models import ScanResult

ROOT = Path(__file__).resolve().parent
BENCH = ROOT / "benchmark"
RESULTS = BENCH / "results"

# Canonical arm order for the ablation (baseline.json is the D12 historical twin
# of static and is left out of the headline table to avoid a duplicate row).
ARM_ORDER = ["static", "ai", "ai_repair", "full", "zap", "crapi"]
ARM_LABEL = {
    "static": "Static payloads",
    "ai": "AI payloads",
    "ai_repair": "AI + self-repair",
    "full": "Full (BOLA engine)",
    "zap": "OWASP ZAP (baseline)",
    "crapi": "crAPI (2nd target)",
}


def _load_run_eval():
    """Load benchmark/run_eval.py by path (it is a script dir, not a package)."""
    spec = importlib.util.spec_from_file_location("run_eval", BENCH / "run_eval.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["run_eval"] = module  # dataclass annotation resolution needs it registered
    spec.loader.exec_module(module)
    return module


def load_result(path: Path) -> ScanResult:
    return ScanResult.model_validate_json(path.read_text(encoding="utf-8"))


def arm_result_paths() -> list[Path]:
    """The canonical arm JSONs, in ARM_ORDER, that actually exist on disk."""
    out = []
    for stem in ARM_ORDER:
        p = RESULTS / f"{stem}.json"
        if p.exists():
            out.append(p)
    return out


def ablation_rows(run_eval, gt, paths: list[Path]) -> list[dict]:
    """Score each arm against the ground truth -> one plain-dict row per arm."""
    rows = []
    for path in paths:
        result = load_result(path)
        m = run_eval.evaluate(path.stem, result, gt)
        rows.append({
            "Arm": ARM_LABEL.get(path.stem, path.stem),
            "Target": m.target,
            "Known": len(gt.for_target(m.target)),
            "TP": m.tp, "FP": m.fp, "FN": m.fn,
            "Precision": round(m.precision, 2),
            "Recall": round(m.recall, 2),
            "F1": round(m.f1, 2),
            "Requests": m.requests_sent if m.requests_sent else None,  # None -> n/a
            "_stem": path.stem,
        })
    return rows


def bola_findings(result: ScanResult) -> list:
    return [f for f in result.findings if f.scanner == "bola" and f.ai_trace is not None]


def parse_oracle(raw_response: str) -> dict:
    """Best-effort parse of the schema-validated oracle response for display."""
    try:
        return json.loads(raw_response)
    except (ValueError, TypeError):
        return {}


# --------------------------------------------------------------------------- #
# Streamlit UI (everything below touches st.*; kept out of the pure helpers)
# --------------------------------------------------------------------------- #
def main() -> None:  # pragma: no cover - exercised by `streamlit run`, not pytest
    import pandas as pd
    import streamlit as st

    from apiguard.report.generator import render_report

    st.set_page_config(page_title="APIGuard", page_icon="🛡️", layout="wide")
    run_eval = _load_run_eval()
    gt = run_eval.load_ground_truth()
    paths = arm_result_paths()

    st.title("🛡️ APIGuard")
    st.caption(
        "AI-powered API vulnerability scanner — detecting BOLA/IDOR flaws that return a "
        "normal 200 OK and are invisible to status-code scanners."
    )
    st.info("Offline demo — every panel is read from committed result files "
            "(`benchmark/results/`). No live target, no network, no Ollama required.", icon="📴")

    rows = ablation_rows(run_eval, gt, paths)
    vampi = {r["_stem"]: r for r in rows if r["Target"] == "vampi"}
    c1, c2, c3 = st.columns(3)
    if "full" in vampi:
        c1.metric("APIGuard Full — recall", f"{vampi['full']['Recall']:.2f}", help="8/12 VAmPI vulns, 0 FP")
    if "zap" in vampi:
        c2.metric("OWASP ZAP — recall", f"{vampi['zap']['Recall']:.2f}",
                  delta=f"{(vampi['zap']['Recall'] - vampi['full']['Recall']):+.2f} vs Full" if "full" in vampi else None,
                  help="ZAP misses every authorization vuln APIGuard's engine catches")
    if "full" in vampi:
        c3.metric("APIGuard Full — precision", f"{vampi['full']['Precision']:.2f}")

    tab_abl, tab_find, tab_bola, tab_report, tab_about = st.tabs(
        ["📊 Ablation", "🔍 Findings", "🧠 BOLA deep-dive", "📄 Report", "ℹ️ About"]
    )

    # ---- Ablation ----
    with tab_abl:
        st.subheader("Ablation — precision / recall / F1 vs ground truth")
        df = pd.DataFrame([{k: v for k, v in r.items() if not k.startswith("_")} for r in rows])
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.caption("Recall = TP / known vulns for that target. Precision = TP / (TP+FP). "
                   "ZAP's request count is not in its report (n/a).")
        vrows = [r for r in rows if r["Target"] == "vampi"]
        if vrows:
            chart = pd.DataFrame({r["Arm"]: [r["Recall"]] for r in vrows}).T
            chart.columns = ["Recall"]
            st.bar_chart(chart, use_container_width=True)
        st.markdown(
            "**The result:** the BOLA/BFLA engine lifts recall from **0.42** (baseline scanners) "
            "to **0.67** at perfect precision — nearly **4×** OWASP ZAP's 0.17. ZAP retrieved the "
            "`/users/v1/_debug` password dump and cross-user data and flagged nothing: it cannot "
            "reason about authorization."
        )

    # ---- Findings explorer ----
    with tab_find:
        labels = {ARM_LABEL.get(p.stem, p.stem): p for p in paths}
        pick = st.selectbox("Arm", list(labels), index=list(labels).index(ARM_LABEL["full"])
                            if ARM_LABEL["full"] in labels else 0)
        result = load_result(labels[pick])
        counts = result.severity_counts()
        st.write(f"**{len(result.findings)}** findings · "
                 + " · ".join(f"{k} {v}" for k, v in counts.items() if v)
                 + f" · {result.requests_sent or 'n/a'} requests · model {result.model} seed {result.seed}")
        for f in result.findings:
            with st.expander(f"{f.severity.value.upper()} · {f.owasp_id} · {f.title}"):
                st.markdown(f"`{f.endpoint.method} {f.endpoint.path}` · scanner **{f.scanner}** · "
                            f"confidence **{f.confidence:.2f}**")
                st.markdown(f"**What:** {f.description}")
                st.markdown(f"**Fix:** {f.remediation}")
                if f.ai_trace and f.ai_trace.signals:
                    st.bar_chart(pd.DataFrame({"signal": list(f.ai_trace.signals),
                                               "value": list(f.ai_trace.signals.values())})
                                 .set_index("signal"), use_container_width=True)
                st.code(f.evidence.curl_repro, language="bash")
                st.text(f"HTTP {f.evidence.response_status}")
                st.code((f.evidence.response_body or "")[:2000], language="json")

    # ---- BOLA deep-dive ----
    with tab_bola:
        st.subheader("The crown jewel — semantic BOLA adjudication")
        st.caption("A cross-user access that returns 200 OK looks fine to a status scanner. "
                   "APIGuard runs deterministic gates first, then an LLM oracle only on ambiguous "
                   "cases, and computes confidence from measurable signals — never asked of the model.")
        full = next((load_result(p) for p in paths if p.stem == "full"), None)
        crapi = next((load_result(p) for p in paths if p.stem == "crapi"), None)
        pool = (bola_findings(full) if full else []) + (bola_findings(crapi) if crapi else [])
        if not pool:
            st.warning("No AI-adjudicated BOLA findings in the saved arms.")
        else:
            f = pool[st.selectbox("BOLA finding", range(len(pool)),
                                  format_func=lambda i: f"{pool[i].endpoint.method} {pool[i].endpoint.path}")]
            oracle = parse_oracle(f.ai_trace.raw_response)
            m1, m2, m3 = st.columns(3)
            m1.metric("Confidence (computed)", f"{f.confidence:.2f}")
            m2.metric("Oracle verdict", "LEAK" if oracle.get("is_leak") else "—")
            m3.metric("Model / seed", f"{f.ai_trace.model} · {f.ai_trace.seed}")
            st.markdown("**Confidence signals** (weighted mean → confidence):")
            st.bar_chart(pd.DataFrame({"signal": list(f.ai_trace.signals),
                                       "value": list(f.ai_trace.signals.values())}).set_index("signal"),
                         use_container_width=True)
            if oracle.get("leaked_fields"):
                st.markdown(f"**Leaked fields:** `{', '.join(oracle['leaked_fields'])}`")
            if oracle.get("reasoning"):
                st.markdown(f"**Oracle reasoning:** {oracle['reasoning']}")
            with st.expander("Oracle prompt (User A's response vs User B's cross-access)"):
                st.code(f.ai_trace.prompt[:6000])
            with st.expander("The leak — User B's cross-access response"):
                st.code(f.evidence.curl_repro, language="bash")
                st.code((f.evidence.response_body or "")[:3000], language="json")

    # ---- Report ----
    with tab_report:
        labels = {ARM_LABEL.get(p.stem, p.stem): p for p in paths}
        pick = st.selectbox("Report for arm", list(labels),
                            index=list(labels).index(ARM_LABEL["full"]) if ARM_LABEL["full"] in labels else 0,
                            key="report_arm")
        html = render_report(load_result(labels[pick]))
        st.download_button("⬇️ Download HTML report", html, file_name=f"apiguard_{labels[pick].stem}.html",
                           mime="text/html")
        st.components.v1.html(html, height=680, scrolling=True)

    # ---- About ----
    with tab_about:
        st.markdown(
            "### What this is\n"
            "APIGuard parses an OpenAPI spec, attacks every endpoint, and uses a **locally-hosted "
            "LLM** to (a) generate context-aware payloads and (b) adjudicate whether a cross-user "
            "access actually leaked data — catching **BOLA/IDOR** flaws that return 200 OK.\n\n"
            "### Why it's defensible\n"
            "- **Deterministic first, LLM second** — the oracle is called only on genuinely ambiguous cases.\n"
            "- **Confidence is computed** from measurable signals + the oracle's binary verdict, never asked of the model.\n"
            "- **Every finding carries evidence** — full request/response + a copy-paste `curl`.\n"
            "- **Reproducible** — every LLM call pins a seed; each result file records model + seed.\n\n"
            "### Result\n"
            "On VAmPI, the Full engine finds **8/12** known vulns at **1.00** precision — the three "
            "the baseline misses are all **authorization** flaws (book-secret BOLA, public-user BOLA, "
            "`_debug` BFLA). OWASP ZAP finds **2/12**. Author: Mayurdhvajsinh."
        )


if __name__ == "__main__":
    main()

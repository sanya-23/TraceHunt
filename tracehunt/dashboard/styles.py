"""Custom CSS and styling tokens for TraceHunt Analyst Dashboard.

Provides a clean, professional, light-themed blue-and-white security operations
center aesthetic with high visual polish, crisp typography, and clear threat badges.
"""

SOC_THEME_CSS = """
<style>
/* Main Container & Typography */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    color: #0f172a;
}

/* App Header Styling */
.soc-header {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%);
    padding: 24px 32px;
    border-radius: 12px;
    color: #ffffff;
    margin-bottom: 24px;
    box-shadow: 0 4px 6px -1px rgba(15, 23, 42, 0.08);
}
.soc-header h1 {
    font-size: 26px;
    font-weight: 700;
    margin: 0 0 6px 0;
    color: #ffffff;
    letter-spacing: -0.5px;
}
.soc-header p {
    font-size: 13px;
    color: #94a3b8;
    margin: 0;
}

/* Metric Cards */
.soc-metric-card {
    background: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 18px 20px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.03);
    margin-bottom: 12px;
}
.soc-metric-title {
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    color: #64748b;
    letter-spacing: 0.5px;
}
.soc-metric-value {
    font-size: 26px;
    font-weight: 700;
    color: #1e3a8a;
    margin-top: 4px;
}
.soc-metric-sub {
    font-size: 11px;
    color: #94a3b8;
    margin-top: 2px;
}

/* Badges */
.badge-crit {
    background-color: #fee2e2;
    color: #991b1b;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}
.badge-high {
    background-color: #ffedd5;
    color: #9a3412;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}
.badge-med {
    background-color: #fef3c7;
    color: #92400e;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}
.badge-low {
    background-color: #e0f2fe;
    color: #075985;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}
.badge-open {
    background-color: #dbeafe;
    color: #1e40af;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}
.badge-tp {
    background-color: #fee2e2;
    color: #b91c1c;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}
.badge-fp {
    background-color: #f1f5f9;
    color: #475569;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 700;
}

/* Code Snippet Blocks */
.cmd-block {
    background: #0f172a;
    color: #38bdf8;
    font-family: 'JetBrains Mono', monospace;
    font-size: 12px;
    padding: 8px 12px;
    border-radius: 6px;
    overflow-x: auto;
    word-break: break-all;
}

/* Empty State Box */
.empty-state {
    text-align: center;
    padding: 48px 24px;
    background: #f8fafc;
    border: 2px dashed #cbd5e1;
    border-radius: 8px;
    color: #64748b;
    margin: 24px 0;
}
.empty-state h3 {
    font-size: 16px;
    font-weight: 600;
    color: #334155;
    margin-bottom: 6px;
}
</style>
"""


def apply_theme():
    """Inject SOC CSS theme into current Streamlit session."""
    import streamlit as st
    st.markdown(SOC_THEME_CSS, unsafe_allow_html=True)


# Backwards-compatible aliases
load_soc_css = apply_theme


def render_severity_badge(severity: str) -> str:
    """Return HTML snippet for severity badge."""
    sev = (severity or "LOW").upper()
    css_class = {
        "CRITICAL": "badge-crit",
        "HIGH": "badge-high",
        "MEDIUM": "badge-med",
        "LOW": "badge-low",
    }.get(sev, "badge-low")
    return f'<span class="{css_class}">{sev}</span>'


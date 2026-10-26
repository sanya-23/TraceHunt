"""Executive HTML Report Renderer.

Renders factual ReportData into a self-contained, executive HTML report with
strict autoescaping against Cross-Site Scripting (XSS), path traversal protection,
and professional cybersecurity operational aesthetics.
"""

import html
from pathlib import Path
import re
from jinja2 import Environment, select_autoescape

from tracehunt.config import settings
from tracehunt.exceptions import ReportExportError
from tracehunt.logging_config import get_logger
from tracehunt.reporting.schema import ReportData

logger = get_logger("reporting.html")

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>TraceHunt Security Report — {{ data.metadata.report_id }}</title>
  <style>
    :root {
      --primary: #1e3a8a;
      --primary-light: #3b82f6;
      --bg: #f8fafc;
      --card-bg: #ffffff;
      --text: #0f172a;
      --text-muted: #64748b;
      --border: #e2e8f0;
      --crit: #ef4444;
      --high: #f97316;
      --med: #f59e0b;
      --low: #3b82f6;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.5;
      padding: 32px 16px;
    }
    .container { max-width: 1100px; margin: 0 auto; }
    .header {
      background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%);
      color: #ffffff;
      padding: 32px;
      border-radius: 12px;
      margin-bottom: 24px;
      box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1);
    }
    .header h1 { font-size: 28px; font-weight: 700; margin-bottom: 8px; letter-spacing: -0.5px; }
    .header .meta { display: flex; flex-wrap: wrap; gap: 16px; font-size: 14px; color: #94a3b8; }
    .header .meta span { display: inline-flex; align-items: center; }
    .badge {
      display: inline-block;
      padding: 3px 8px;
      font-size: 11px;
      font-weight: 700;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }
    .badge-crit { background: #fee2e2; color: #991b1b; }
    .badge-high { background: #ffedd5; color: #9a3412; }
    .badge-med { background: #fef3c7; color: #92400e; }
    .badge-low { background: #e0f2fe; color: #075985; }
    .badge-status { background: #dcfce7; color: #166534; }
    .grid-metrics {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .metric-card {
      background: var(--card-bg);
      padding: 20px;
      border-radius: 8px;
      border: 1px solid var(--border);
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .metric-card .title { font-size: 13px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; }
    .metric-card .value { font-size: 28px; font-weight: 700; margin-top: 4px; color: var(--primary); }
    .section {
      background: var(--card-bg);
      border-radius: 8px;
      border: 1px solid var(--border);
      padding: 24px;
      margin-bottom: 24px;
      box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    .section h2 { font-size: 18px; font-weight: 700; margin-bottom: 16px; color: var(--primary); border-bottom: 2px solid var(--border); padding-bottom: 8px; }
    table { width: 100%; border-collapse: collapse; margin-top: 12px; font-size: 13px; }
    th { text-align: left; padding: 10px 12px; background: #f1f5f9; color: var(--text-muted); font-weight: 600; border-bottom: 1px solid var(--border); }
    td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
    tr:hover td { background: #f8fafc; }
    .code-block {
      background: #0f172a;
      color: #38bdf8;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 12px;
      padding: 8px 12px;
      border-radius: 6px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .finding-card {
      border: 1px solid var(--border);
      border-left: 4px solid var(--high);
      border-radius: 6px;
      padding: 16px;
      margin-bottom: 12px;
      background: #fafafa;
    }
    .finding-card.CRITICAL { border-left-color: var(--crit); }
    .finding-card.HIGH { border-left-color: var(--high); }
    .finding-card.MEDIUM { border-left-color: var(--med); }
    .finding-card.LOW { border-left-color: var(--low); }
    .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; }
    .finding-rule { font-size: 15px; font-weight: 700; color: var(--text); }
    .callout {
      background: #eff6ff;
      border-left: 4px solid var(--primary-light);
      padding: 16px;
      border-radius: 6px;
      font-size: 13px;
      color: #1e40af;
      margin-top: 16px;
    }
    .footer { text-align: center; font-size: 12px; color: var(--text-muted); margin-top: 32px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>TraceHunt Threat Hunting Report</h1>
      <div class="meta">
        <span><strong>Report ID:</strong>&nbsp;{{ data.metadata.report_id }}</span>
        <span><strong>Generated:</strong>&nbsp;{{ data.metadata.generated_at }}</span>
        <span><strong>Target Host:</strong>&nbsp;{{ data.metadata.host or "All Observed Hosts" }}</span>
        {% if data.metadata.investigation_id %}
        <span><strong>Case ID:</strong>&nbsp;{{ data.metadata.investigation_id }}</span>
        {% endif %}
      </div>
    </div>

    <!-- Executive Metrics Grid -->
    <div class="grid-metrics">
      <div class="metric-card">
        <div class="title">Total Events Analyzed</div>
        <div class="value">{{ data.metrics.total_events }}</div>
      </div>
      <div class="metric-card">
        <div class="title">Findings Detected</div>
        <div class="value" style="color: {% if data.metrics.total_findings > 0 %}var(--crit){% else %}var(--primary){% endif %};">
          {{ data.metrics.total_findings }}
        </div>
      </div>
      <div class="metric-card">
        <div class="title">Critical / High Alerts</div>
        <div class="value" style="color: var(--high);">
          {{ data.metrics.severity_counts.CRITICAL + data.metrics.severity_counts.HIGH }}
        </div>
      </div>
      <div class="metric-card">
        <div class="title">Investigation Status</div>
        <div class="value" style="font-size: 20px; padding-top: 6px;">
          {% if data.case %}
          <span class="badge badge-status">{{ data.case.status }}</span>
          {% else %}
          <span class="badge badge-low">TELEMETRY AUDIT</span>
          {% endif %}
        </div>
      </div>
    </div>

    <!-- Investigation Case Details (if present) -->
    {% if data.case %}
    <div class="section">
      <h2>Investigation Case Overview</h2>
      <table>
        <tr>
          <th style="width: 20%;">Case ID</th>
          <td><strong>{{ data.case.id }}</strong></td>
          <th style="width: 20%;">Current Status</th>
          <td><span class="badge badge-status">{{ data.case.status }}</span></td>
        </tr>
        <tr>
          <th>Case Title</th>
          <td colspan="3">{{ data.case.title }}</td>
        </tr>
        {% if data.case.summary %}
        <tr>
          <th>Summary / Disposition Rationale</th>
          <td colspan="3">{{ data.case.summary }}</td>
        </tr>
        {% endif %}
        <tr>
          <th>Host Scope</th>
          <td>{{ data.case.host }}</td>
          <th>Created / Updated</th>
          <td>{{ data.case.created_at }} / {{ data.case.updated_at }}</td>
        </tr>
      </table>

      {% if data.case.audit_trail %}
      <h3 style="font-size: 14px; font-weight: 700; margin-top: 16px; margin-bottom: 8px;">Case Review Audit Trail</h3>
      <table>
        <thead>
          <tr>
            <th>Timestamp</th>
            <th>Reviewer</th>
            <th>Action</th>
            <th>Notes & Transition Details</th>
          </tr>
        </thead>
        <tbody>
          {% for a in data.case.audit_trail %}
          <tr>
            <td style="white-space: nowrap;">{{ a.created_at }}</td>
            <td><strong>{{ a.reviewer }}</strong></td>
            <td><span class="badge badge-low">{{ a.action }}</span></td>
            <td>{{ a.comment }}</td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% endif %}
    </div>
    {% endif %}

    <!-- Findings Section -->
    <div class="section">
      <h2>Behavioral Detection Findings ({{ data.findings|length }})</h2>
      {% if data.findings %}
        {% for f in data.findings %}
        <div class="finding-card {{ f.severity }}">
          <div class="finding-header">
            <span class="finding-rule">
              {{ f.rule_id }} — Finding #{{ f.id }}
            </span>
            <span>
              <span class="badge badge-{{ f.severity|lower }}">{{ f.severity }}</span>
              <span class="badge badge-low">Conf: {{ f.confidence }}</span>
            </span>
          </div>
          <p style="margin-bottom: 8px; font-size: 14px;"><strong>Rationale:</strong> {{ f.rationale }}</p>
          {% if f.command_line %}
          <div style="margin-bottom: 8px;">
            <div style="font-size: 11px; font-weight: 600; color: var(--text-muted); margin-bottom: 4px;">EXECUTED COMMAND LINE:</div>
            <div class="code-block">{{ f.command_line }}</div>
          </div>
          {% endif %}
          {% if f.process_image %}
          <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 4px;">
            <strong>Process Image:</strong> {{ f.process_image }}
          </p>
          {% endif %}
          {% if f.caveats %}
          <p style="font-size: 12px; color: var(--text-muted); font-style: italic;">
            <strong>Analyst Caveats:</strong> {{ f.caveats }}
          </p>
          {% endif %}
        </div>
        {% endfor %}
      {% else %}
        <p style="color: var(--text-muted); font-style: italic;">Zero behavioral detection findings flagged for this host and timeframe.</p>
      {% endif %}
    </div>

    <!-- Timeline Highlights -->
    <div class="section">
      <h2>Chronological Endpoint Telemetry Sample</h2>
      {% if data.timeline %}
      <table>
        <thead>
          <tr>
            <th>Timestamp (UTC)</th>
            <th>Type</th>
            <th>PID</th>
            <th>User</th>
            <th>Process / Command Summary</th>
            <th>Detection</th>
          </tr>
        </thead>
        <tbody>
          {% for t in data.timeline[:50] %}
          <tr>
            <td style="white-space: nowrap;">{{ t.event_time }}</td>
            <td><span class="badge badge-low">{{ t.event_type }}</span></td>
            <td>{{ t.process_id or "-" }}</td>
            <td>{{ t.user or "-" }}</td>
            <td>
              <div style="max-width: 450px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                {{ t.command_line or t.image or t.ip_address or "-" }}
              </div>
            </td>
            <td>
              {% if t.has_detection %}
              <span class="badge badge-{{ (t.max_severity or 'high')|lower }}">{{ t.max_severity }}</span>
              {% else %}
              <span style="color: var(--text-muted); font-size: 11px;">Benign</span>
              {% endif %}
            </td>
          </tr>
          {% endfor %}
        </tbody>
      </table>
      {% if data.timeline|length > 50 %}
      <p style="font-size: 12px; color: var(--text-muted); margin-top: 8px;">
        Showing top 50 of {{ data.timeline|length }} events. Complete event records available via JSON export.
      </p>
      {% endif %}
      {% else %}
      <p style="color: var(--text-muted); font-style: italic;">No endpoint activity recorded within the selected parameters.</p>
      {% endif %}
    </div>

    <!-- Analytical Limitations & Disclaimers -->
    <div class="section">
      <h2>Analytical Scope & Forensics Limitations</h2>
      <ul style="padding-left: 20px; font-size: 13px; color: var(--text-muted);">
        {% for lim in data.limitations %}
        <li style="margin-bottom: 6px;">{{ lim }}</li>
        {% endfor %}
      </ul>
      <div class="callout">
        <strong>TraceHunt Defensive Assurance:</strong> This document was generated automatically by the TraceHunt Defensive Threat-Hunting Platform. All reported metrics, findings, and case timelines reflect real telemetry recorded in the verified relational database.
      </div>
    </div>

    <div class="footer">
      Generated by TraceHunt Endpoint Threat Hunting Platform v1.0.0 &bull; For Authorized Defensive Use Only
    </div>
  </div>
</body>
</html>
"""


def _sanitize_filename(name: str) -> str:
    """Sanitize filename to prevent directory traversal and invalid characters."""
    clean = re.sub(r"[^\w\-.]", "_", name)
    clean = clean.strip("._")
    if not clean:
        clean = "tracehunt_report"
    return clean


def render_html_report(report_data: ReportData, filename: str | None = None) -> Path:
    """Render ReportData to an executive HTML file with strict XSS autoescaping."""
    settings.ensure_directories()

    default_name = f"{report_data.metadata.report_id}.html"
    raw_name = filename or default_name
    safe_name = _sanitize_filename(raw_name)
    if not safe_name.endswith(".html"):
        safe_name += ".html"

    target_path = (settings.REPORTS_DIR / safe_name).resolve()

    # Path traversal protection
    if not str(target_path).startswith(str(settings.REPORTS_DIR.resolve())):
        raise ReportExportError("Path traversal detected in report filename.")

    try:
        # Jinja2 environment configured with strict autoescaping
        env = Environment(autoescape=select_autoescape(["html", "xml"]))
        template = env.from_string(HTML_TEMPLATE)

        rendered_html = template.render(data=report_data)

        with open(target_path, "w", encoding="utf-8") as f:
            f.write(rendered_html)

        logger.info(f"Rendered executive HTML report to {target_path}")
        return target_path
    except Exception as e:
        logger.error(f"Failed to render HTML report: {e}", exc_info=True)
        raise ReportExportError(f"Failed to render HTML report: {e}") from e

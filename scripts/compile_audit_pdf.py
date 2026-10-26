"""Compile TRACEHUNT_COMPREHENSIVE_AUDIT_REPORT.md into a print-ready vector PDF via Chrome."""

import html
import re
import subprocess
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MD_PATH = BASE_DIR / "reports" / "TRACEHUNT_COMPREHENSIVE_AUDIT_REPORT.md"
PDF_PATH = BASE_DIR / "reports" / "TRACEHUNT_COMPREHENSIVE_AUDIT_REPORT.pdf"
TMP_HTML = Path("/tmp/tracehunt_audit_report.html")


def md_to_html(md_text: str) -> str:
    lines = md_text.split("\n")
    html_lines = []
    in_table = False
    in_code = False
    code_block = []

    for line in lines:
        # Code block handling
        if line.startswith("```"):
            if in_code:
                in_code = False
                escaped_code = html.escape("\n".join(code_block))
                html_lines.append(f"<pre><code>{escaped_code}</code></pre>")
                code_block = []
            else:
                in_code = True
                code_block = []
            continue

        if in_code:
            code_block.append(line)
            continue

        # Table handling
        if line.strip().startswith("|") and line.strip().endswith("|"):
            cells = [c.strip() for c in line.strip()[1:-1].split("|")]
            # Skip separator line | :--- | :--- |
            if all(re.match(r"^:?-+:?$", c) for c in cells):
                continue
            if not in_table:
                in_table = True
                html_lines.append('<div class="table-wrap"><table>')
                # Header row
                th_html = "".join(f"<th>{parse_inline(c)}</th>" for c in cells)
                html_lines.append(f"<thead><tr>{th_html}</tr></thead><tbody>")
            else:
                td_html = "".join(f"<td>{parse_inline(c)}</td>" for c in cells)
                html_lines.append(f"<tr>{td_html}</tr>")
            continue
        else:
            if in_table:
                in_table = False
                html_lines.append("</tbody></table></div>")

        stripped = line.strip()
        if not stripped:
            continue

        # Headings
        if stripped.startswith("# "):
            html_lines.append(f"<h1>{parse_inline(stripped[2:])}</h1>")
        elif stripped.startswith("## "):
            html_lines.append(f"<h2>{parse_inline(stripped[3:])}</h2>")
        elif stripped.startswith("### "):
            html_lines.append(f"<h3>{parse_inline(stripped[4:])}</h3>")
        elif stripped.startswith("#### "):
            html_lines.append(f"<h4>{parse_inline(stripped[5:])}</h4>")
        elif stripped == "---":
            html_lines.append("<hr>")
        elif stripped.startswith("- ") or stripped.startswith("* "):
            html_lines.append(f"<li>{parse_inline(stripped[2:])}</li>")
        elif re.match(r"^\d+\.\s", stripped):
            content = re.sub(r"^\d+\.\s", "", stripped)
            html_lines.append(f"<li>{parse_inline(content)}</li>")
        else:
            html_lines.append(f"<p>{parse_inline(stripped)}</p>")

    if in_table:
        html_lines.append("</tbody></table></div>")

    return "\n".join(html_lines)


def parse_inline(text: str) -> str:
    # Escape basic html characters first
    text = html.escape(text)
    # Restore basic formatting
    # Bold **text**
    text = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", text)
    # Italic *text*
    text = re.sub(r"\*(.+?)\*", r"<em>\1</em>", text)
    # Code `code`
    text = re.sub(r"`(.+?)`", r"<code>\1</code>", text)
    # Links [text](url)
    text = re.sub(r"\[(.+?)\]\((.+?)\)", r'<span class="link">\1</span>', text)
    # Math symbols
    text = text.replace("&amp;ge;", "≥").replace("&amp;le;", "≤").replace("&amp;gt;", "&gt;").replace("&amp;lt;", "&lt;")
    return text


def main():
    print(f"[+] Reading {MD_PATH}...")
    md_content = MD_PATH.read_text(encoding="utf-8")
    body_html = md_to_html(md_content)

    full_html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>TraceHunt Comprehensive Audit Report</title>
<style>
  @page {{
    size: letter;
    margin: 20mm 15mm 20mm 15mm;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    color: #1e293b;
    background: #ffffff;
    font-size: 11pt;
    line-height: 1.6;
    margin: 0;
    padding: 0;
  }}
  h1 {{
    color: #0f172a;
    font-size: 22pt;
    border-bottom: 3px solid #2563eb;
    padding-bottom: 8px;
    margin-top: 0;
  }}
  h2 {{
    color: #1e3a8a;
    font-size: 15pt;
    border-bottom: 1px solid #cbd5e1;
    padding-bottom: 6px;
    margin-top: 24pt;
    page-break-after: avoid;
  }}
  h3 {{
    color: #1e40af;
    font-size: 12pt;
    margin-top: 16pt;
    page-break-after: avoid;
  }}
  h4 {{
    color: #334155;
    font-size: 11pt;
    margin-top: 12pt;
    page-break-after: avoid;
  }}
  p, li {{
    color: #334155;
    text-align: justify;
  }}
  ul, ol {{
    padding-left: 20px;
  }}
  li {{
    margin-bottom: 4px;
  }}
  hr {{
    border: none;
    border-top: 1px solid #e2e8f0;
    margin: 20px 0;
  }}
  .table-wrap {{
    margin: 14pt 0;
    page-break-inside: avoid;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 9.5pt;
  }}
  th, td {{
    border: 1px solid #cbd5e1;
    padding: 6px 10px;
    text-align: left;
    vertical-align: top;
  }}
  th {{
    background-color: #f1f5f9;
    color: #0f172a;
    font-weight: 600;
  }}
  tr:nth-child(even) {{
    background-color: #f8fafc;
  }}
  pre {{
    background-color: #0f172a;
    color: #f8fafc;
    padding: 12px;
    border-radius: 6px;
    font-family: 'SF Mono', Monaco, Menlo, Consolas, monospace;
    font-size: 8.5pt;
    line-height: 1.4;
    overflow-x: auto;
    page-break-inside: avoid;
  }}
  code {{
    font-family: 'SF Mono', Monaco, Menlo, Consolas, monospace;
    font-size: 9pt;
    background-color: #f1f5f9;
    color: #0f172a;
    padding: 2px 4px;
    border-radius: 4px;
    border: 1px solid #e2e8f0;
  }}
  pre code {{
    background-color: transparent;
    color: inherit;
    border: none;
    padding: 0;
  }}
  .link {{
    color: #2563eb;
    font-weight: 500;
  }}
  strong {{
    color: #0f172a;
  }}
</style>
</head>
<body>
{body_html}
</body>
</html>
"""
    HTML_PATH = BASE_DIR / "reports" / "TRACEHUNT_COMPREHENSIVE_AUDIT_REPORT.html"
    HTML_PATH.write_text(full_html, encoding="utf-8")
    print(f"[+] Saved styled HTML report to {HTML_PATH} ({HTML_PATH.stat().st_size:,} bytes)")

    print(f"[+] Rendering vector PDF via Chrome to {PDF_PATH}...")
    cmd = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "--headless=new",
        "--disable-gpu",
        "--no-pdf-header-footer",
        f"--print-to-pdf={PDF_PATH}",
        f"file://{HTML_PATH}",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode == 0 and PDF_PATH.exists():
        print(f"[+] SUCCESS! Generated vector PDF report: {PDF_PATH} ({PDF_PATH.stat().st_size:,} bytes)")
    else:
        print(f"[-] Error generating PDF: {proc.stderr}")


if __name__ == "__main__":
    main()


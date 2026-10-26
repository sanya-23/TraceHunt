"""Automated Visual Screenshot Capture via Chrome DevTools Protocol (CDP).

Captures genuine, high-resolution screenshots of all TraceHunt UI views and API docs
directly from the live running servers on localhost.
"""

import asyncio
import base64
import json
import subprocess
import time
import urllib.request
from pathlib import Path

SCREENSHOTS_DIR = Path(__file__).resolve().parent.parent / "evidence" / "screenshots"
SCREENSHOTS_DIR.mkdir(parents=True, exist_ok=True)


async def send_cdp(ws, msg_id, method, params=None):
    payload = {"id": msg_id, "method": method}
    if params:
        payload["params"] = params
    await ws.send(json.dumps(payload))
    while True:
        raw = await ws.recv()
        resp = json.loads(raw)
        if resp.get("id") == msg_id:
            return resp


async def capture_tab(ws, name, click_target=None, extra_wait=3.0):
    if click_target:
        click_js = f"""
        (function() {{
            const els = Array.from(document.querySelectorAll('[data-testid="stMarkdownContainer"] p, [data-testid="stWidgetLabel"] p, label p'));
            const target = els.find(el => el.textContent.includes('{click_target}'));
            if (target) {{
                target.click();
                return 'clicked ' + target.textContent;
            }}
            return 'not found';
        }})()
        """
        res = await send_cdp(ws, 100, "Runtime.evaluate", {"expression": click_js})
        print(f"Clicked navigation target '{click_target}':", res.get("result", {}).get("result", {}).get("value"))
        await asyncio.sleep(extra_wait)

    # Capture full screenshot
    res = await send_cdp(ws, 200, "Page.captureScreenshot", {"format": "png"})
    img_bytes = base64.b64decode(res["result"]["data"])
    out_path = SCREENSHOTS_DIR / name
    out_path.write_bytes(img_bytes)
    print(f"Saved: {out_path.name} ({len(img_bytes)} bytes)")


async def main():
    import websockets

    # 1. Start headless Chrome
    print("[+] Launching Google Chrome in headless mode with remote debugging...")
    chrome_proc = subprocess.Popen([
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "--headless=new",
        "--remote-debugging-port=9222",
        "--disable-gpu",
        "--window-size=1440,900",
    ])
    time.sleep(2.0)

    try:
        # Open Streamlit tab
        req = urllib.request.Request("http://127.0.0.1:9222/json/new?http://localhost:8501", method="PUT")
        with urllib.request.urlopen(req) as resp:
            tab_info = json.loads(resp.read().decode())
        ws_url = tab_info["webSocketDebuggerUrl"]

        async with websockets.connect(ws_url) as ws:
            await send_cdp(ws, 1, "Page.enable")
            print("[+] Connected to Streamlit tab. Waiting 5s for initial render...")
            await asyncio.sleep(5.0)

            # View 1: SOC Overview
            print("[+] Capturing View 1: SOC Overview...")
            await capture_tab(ws, "01-soc_overview.png", "SOC Overview")

            # View 2: Telemetry Ingestion
            print("[+] Capturing View 2: Telemetry Ingestion...")
            await capture_tab(ws, "02-telemetry_ingestion.png", "Telemetry Ingestion")

            # View 3: Host & Process Explorer
            print("[+] Capturing View 3: Host & Process Explorer...")
            await capture_tab(ws, "03-process_tree_dag.png", "Host & Process Explorer")

            # View 4: Host Timeline
            print("[+] Capturing View 4: Host Timeline...")
            await capture_tab(ws, "04-host_timeline.png", "Host Timeline")

            # View 5: Findings & Detections
            print("[+] Capturing View 5: Findings & Detections...")
            await capture_tab(ws, "05-findings_detections.png", "Findings & Detections")

            # View 6: Investigation Cases
            print("[+] Capturing View 6: Investigation Cases...")
            await capture_tab(ws, "06-investigation_cases.png", "Investigation Cases")

            # View 7: Report Generator
            print("[+] Capturing View 7: Report Generator...")
            await capture_tab(ws, "07-report_generator.png", "Report Generator")

        # View 8: FastAPI Swagger Documentation
        print("[+] Opening FastAPI Swagger tab...")
        req_swagger = urllib.request.Request("http://127.0.0.1:9222/json/new?http://127.0.0.1:8000/docs", method="PUT")
        with urllib.request.urlopen(req_swagger) as resp:
            swagger_info = json.loads(resp.read().decode())
        swagger_ws = swagger_info["webSocketDebuggerUrl"]

        async with websockets.connect(swagger_ws) as ws_sw:
            await send_cdp(ws_sw, 1, "Page.enable")
            await asyncio.sleep(3.0)
            await capture_tab(ws_sw, "08-fastapi_swagger_docs.png")

        print("[+] All genuine UI & API screenshots captured successfully!")

    finally:
        chrome_proc.terminate()


if __name__ == "__main__":
    asyncio.run(main())

"""Capture screenshot of Report Generator after clicking 'Generate Investigation Report'."""

import asyncio
import base64
import json
import subprocess
import time
import urllib.request
from pathlib import Path
import websockets

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


async def main():
    chrome_cmd = [
        "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
        "--headless=new",
        "--remote-debugging-port=9223",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--window-size=1440,1100",
        "http://localhost:8501",
    ]
    proc = subprocess.Popen(chrome_cmd)
    try:
        await asyncio.sleep(3.0)
        # Fetch targets
        with urllib.request.urlopen("http://127.0.0.1:9223/json") as resp:
            targets = json.loads(resp.read().decode())
        ws_url = targets[0]["webSocketDebuggerUrl"]

        async with websockets.connect(ws_url) as ws:
            await send_cdp(ws, 1, "Page.enable")
            await send_cdp(ws, 2, "DOM.enable")
            await asyncio.sleep(2.0)

            # Navigate to Report Generator tab
            click_nav_js = """
            (function() {
                const els = Array.from(document.querySelectorAll('[data-testid="stMarkdownContainer"] p, [data-testid="stWidgetLabel"] p, label p'));
                const target = els.find(el => el.textContent.includes('Report Generator'));
                if (target) {
                    target.click();
                    return 'clicked Report Generator';
                }
                return 'not found';
            })()
            """
            res = await send_cdp(ws, 10, "Runtime.evaluate", {"expression": click_nav_js})
            print("Navigated to Report Generator:", res.get("result", {}).get("result", {}).get("value"))
            await asyncio.sleep(3.0)

            # Click the Generate button
            click_btn_js = """
            (function() {
                const btns = Array.from(document.querySelectorAll('button'));
                const btn = btns.find(b => b.textContent.includes('Generate Investigation Report'));
                if (btn) {
                    btn.click();
                    return 'clicked button';
                }
                return 'button not found';
            })()
            """
            res_btn = await send_cdp(ws, 20, "Runtime.evaluate", {"expression": click_btn_js})
            print("Clicked Generate button:", res_btn.get("result", {}).get("result", {}).get("value"))
            # Wait for generation to complete (Chrome headless generates PDF + docx + html + json)
            await asyncio.sleep(5.0)

            # Capture screenshot
            res_snap = await send_cdp(ws, 30, "Page.captureScreenshot", {"format": "png"})
            img_bytes = base64.b64decode(res_snap["result"]["data"])
            out_file = SCREENSHOTS_DIR / "07b-report_generated_downloads.png"
            out_file.write_bytes(img_bytes)
            print(f"[+] Saved generated report screenshot: {out_file} ({len(img_bytes)} bytes)")

    finally:
        proc.terminate()


if __name__ == "__main__":
    asyncio.run(main())

"""Run against a local Vite server. Only the entry mount is isolated, not QR code.

Usage: python3 scripts/test-qr-browser.py http://127.0.0.1:4173
Requires Python Playwright with Chromium. No relay, account, or production keys.
"""
import base64
import json
import os
import shutil
from pathlib import Path
import sys
from urllib.parse import urlparse

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parent.parent
BASE = sys.argv[1] if len(sys.argv) == 2 else "http://127.0.0.1:4173"
assert urlparse(BASE).hostname in ("127.0.0.1", "localhost", "::1")
FIXTURES = ROOT / "android/app/src/test/resources/qr"
PNG = (FIXTURES / "invite-qrencode.png").read_bytes()
MOUNT = """
import React from '/node_modules/.vite/deps/react.js';
import ReactDOM from '/node_modules/.vite/deps/react-dom_client.js';
import {Entrance} from './components/Entrance';
import './styles.css';
window.testLoginCalls = 0;
ReactDOM.createRoot(document.getElementById('root')).render(React.createElement(Entrance, {
  onPreflight: async () => true,
  onLogin: async () => { window.testLoginCalls++; throw Error('test login disabled'); }
}));
"""

with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, executable_path=os.environ.get("ABYSSAL_TEST_CHROMIUM") or shutil.which("chromium"))
    try:
        for width, height in [(1440, 1000), (390, 844)]:
            context = browser.new_context(viewport={"width": width, "height": height})
            context.add_init_script("""
              window.testCameraTracks = [];
              navigator.mediaDevices.getUserMedia = async () => {
                const image = new Image();
                image.src = 'data:image/png;base64,' + """ + json.dumps(base64.b64encode(PNG).decode()) + """;
                await image.decode();
                const canvas = document.createElement('canvas');
                canvas.width = image.naturalWidth;
                canvas.height = image.naturalHeight;
                canvas.getContext('2d').drawImage(image, 0, 0);
                const stream = canvas.captureStream(4);
                window.testCameraTracks.push(...stream.getTracks());
                return stream;
              };
            """)
            page = context.new_page()
            errors = []
            requests = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.on("request", lambda request: requests.append(request.url))
            page.route("**/src/main.tsx", lambda route: route.fulfill(content_type="application/javascript", body=MOUNT))
            page.goto(BASE)
            page.wait_for_load_state("networkidle")
            assert not errors, errors
            expect(page.get_by_role("heading", name="Enter Abyssal")).to_be_visible()
            for filename, mime in [("invite-v1.png", "image/png"), ("invite-v1.jpeg", "image/jpeg"), ("invite-qrencode.png", "image/png")]:
                page.get_by_label("QR image", exact=True).set_input_files({
                    "name": "../../" + filename,
                    "mimeType": mime,
                    "buffer": (FIXTURES / filename).read_bytes(),
                })
                page.wait_for_function("document.getElementById('abyssal-invite').value.startsWith('abyssal:invite:')")
                expect(page.get_by_label("Abyssal invite", exact=True)).to_have_attribute("type", "password")
                assert "abyssal:invite:" not in page.locator("body").inner_text()
                expect(page.get_by_role("button", name="OPEN QR IMAGE")).to_be_enabled()
                assert page.evaluate("window.testLoginCalls") == 0
                page.get_by_label("Abyssal invite", exact=True).fill("")
            for buffer, mime in [(b"<svg><image href='file:///etc/passwd'/></svg>", "image/png"), (PNG, "image/jpeg")]:
                page.get_by_label("QR image", exact=True).set_input_files({"name": "image.png", "mimeType": mime, "buffer": buffer})
                expect(page.get_by_text("QR image not accepted.")).to_be_visible()
                expect(page.get_by_label("Abyssal invite", exact=True)).to_have_value("")
                expect(page.get_by_role("button", name="OPEN QR IMAGE")).to_be_enabled()
            page.get_by_role("button", name="SCAN INVITE", exact=True).click()
            page.wait_for_function("document.getElementById('abyssal-invite').value.startsWith('abyssal:invite:')")
            expect(page.get_by_label("Abyssal invite", exact=True)).to_have_attribute("type", "password")
            assert "abyssal:invite:" not in page.locator("body").inner_text()
            expect(page.get_by_role("button", name="SCAN INVITE", exact=True)).to_be_visible()
            expect(page.get_by_label("Abyssal invite", exact=True)).to_be_focused()
            expect(page.get_by_label("Abyssal invite", exact=True)).to_be_in_viewport()
            assert page.evaluate("window.testCameraTracks.length > 0 && window.testCameraTracks.every(t => t.readyState === 'ended')")
            assert page.evaluate("window.testLoginCalls") == 0
            expect(page.get_by_text("QR image not accepted.")).to_have_count(0)
            assert page.evaluate("document.documentElement.scrollWidth <= innerWidth")
            for field in page.locator(".entrance-form input:not([type=hidden]):not([type=file])").all():
                if field.is_visible():
                    box = field.bounding_box()
                    assert box and box["x"] >= 0 and box["x"] + box["width"] <= width
            boxes = page.locator(".entrance-form button").evaluate_all("els => els.filter(e => e.offsetWidth).map(e => ({w:e.clientWidth, s:e.scrollWidth}))")
            assert all(box["s"] <= box["w"] + 1 for box in boxes), boxes
            assert all(urlparse(url).netloc == urlparse(BASE).netloc for url in requests), requests
            assert not any("/v1/" in url for url in requests), requests
            assert not errors, errors
            page.screenshot(path=f"/tmp/abyssal-invite-qr-{width}.png", full_page=True)
            page.get_by_role("button", name="ENTER", exact=True).scroll_into_view_if_needed()
            expect(page.get_by_role("button", name="ENTER", exact=True)).to_be_in_viewport()
            context.close()
            print(f"QR browser checks passed: {width}x{height}, PNG/JPEG/camera, rejects, no authentication or external request")
    finally:
        browser.close()

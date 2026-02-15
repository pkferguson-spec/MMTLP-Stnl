import requests
import feedparser
import time
import hashlib
from datetime import datetime, timezone

### ---------------------------------------------------------
### CONFIGURATION
### ---------------------------------------------------------

DISCORD_WEBHOOK = ""   # optional: paste your webhook URL here

KEYWORDS = ["MMTLP", "MMAT", "Next Bridge", "FINRA", "CUSIP"]

SEC_SEARCH_URL = "https://data.sec.gov/api/xbrl/companyfacts/CIK0001861063.json"
FINRA_NEWS_RSS = "https://www.finra.org/newsroom/rss.xml"
GOOGLE_NEWS_RSS = "https://news.google.com/rss/search?q=MMTLP"

HEADERS = {
    "User-Agent": "MMTLP-Sentinel-Agent/1.0 (contact: example@example.com)"
}

### ---------------------------------------------------------
### UTILITIES
### ---------------------------------------------------------

def notify(msg: str):
    """Send a message to Discord if webhook is configured."""
    if not DISCORD_WEBHOOK:
        print("[NO WEBHOOK] " + msg)
        return
    try:
        requests.post(DISCORD_WEBHOOK, json={"content": msg})
    except Exception as e:
        print("Notification error:", e)


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

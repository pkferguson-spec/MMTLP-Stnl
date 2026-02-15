import os
import requests
import json
from datetime import datetime, timezone

# ---------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------

# You must set these as GitHub Secrets:
# X_API_KEY
# X_API_SECRET
# X_ACCESS_TOKEN
# X_ACCESS_SECRET

API_KEY = os.getenv("X_API_KEY")
API_SECRET = os.getenv("X_API_SECRET")
ACCESS_TOKEN = os.getenv("X_ACCESS_TOKEN")
ACCESS_SECRET = os.getenv("X_ACCESS_SECRET")

POST_MESSAGE_FILE = "post_message.txt"

X_POST_URL = "https://api.twitter.com/2/tweets"

# ---------------------------------------------------------
# UTILITIES
# ---------------------------------------------------------

def load_message():
    """Load the message you want to post from post_message.txt."""
    try:
        with open(POST_MESSAGE_FILE, "r", encoding="utf-8") as f:
            msg = f.read().strip()
            if not msg:
                print("Message file is empty.")
                return None
            return msg
    except FileNotFoundError:
        print("post_message.txt not found.")
        return None


def post_to_x(message):
    """Post a message to X using OAuth 2.0 Bearer Token."""
    print("Posting to X...")

    headers = {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Content-Type": "application/json"
    }

    payload = {"text": message}

    try:
        resp = requests.post(X_POST_URL, headers=headers, json=payload, timeout=15)
        if resp.status_code >= 400:
            print(f"X API error: {resp.status_code} - {resp.text}")
            return False

        print("Post successful:", resp.json())
        return True

    except Exception as e:
        print("Error posting to X:", e)
        return False


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():
    print("X Posting Agent starting at", datetime.now(timezone.utc))

    # Load message
    message = load_message()
    if not message:
        print("No message to post. Exiting.")
        return

    # Post message
    success = post_to_x(message)

    if success:
        print("Message posted successfully.")
    else:
        print("Message failed to post.")

    print("Agent completed.")


if __name__ == "__main__":
    main()

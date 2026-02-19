import base64
import requests

from json_log import log_event, safe_error_detail

GMAIL_SEND_URL = "https://gmail.googleapis.com/gmail/v1/users/me/messages/send"


def send_gmail_message(access_token: str, to: str, subject: str, body: str):
    raw_message = f"""To: {to}
Subject: {subject}

{body}
"""

    encoded_message = base64.urlsafe_b64encode(
        raw_message.encode("utf-8")
    ).decode("utf-8")

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    payload = {
        "raw": encoded_message
    }

    response = requests.post(
        GMAIL_SEND_URL,
        headers=headers,
        json=payload,
    )

    if response.status_code not in (200, 202):
        log_event(
            {
                "action": "email_send_error",
                "provider": "google",
                "status_code": response.status_code,
                "error": safe_error_detail(response.text),
            }
        )
        raise Exception(response.text)

    return response.json()

import requests

from json_log import log_event, safe_error_detail

GRAPH_SEND_URL = "https://graph.microsoft.com/v1.0/me/sendMail"


def send_outlook_message(access_token: str, to: str, subject: str, body: str):
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json",
    }

    payload = {
        "message": {
            "subject": subject,
            "body": {
                "contentType": "Text",
                "content": body,
            },
            "toRecipients": [
                {
                    "emailAddress": {
                        "address": to
                    }
                }
            ],
        },
        "saveToSentItems": True,
    }

    response = requests.post(
        GRAPH_SEND_URL,
        headers=headers,
        json=payload,
    )

    if response.status_code not in (200, 202):
        log_event(
            {
                "action": "email_send_error",
                "provider": "microsoft",
                "status_code": response.status_code,
                "error": safe_error_detail(response.text),
            }
        )
        raise Exception(response.text)

    return True

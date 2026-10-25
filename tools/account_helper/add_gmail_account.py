
from pathlib import Path
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
import os
import re

BASE = Path(__file__).resolve().parent
CLIENT = Path(os.environ.get("PASEVSU_GOOGLE_CLIENT_SECRET", str(BASE / "client_secret.json")))
ACCOUNTS = Path(os.environ.get("PASEVSU_GMAIL_ACCOUNTS_DIR", str(Path.home() / ".pasevsu_gmail" / "gmail_accounts")))
SCOPES = ["https://www.googleapis.com/auth/gmail.modify"]

def main():
    if not CLIENT.is_file():
        raise FileNotFoundError(f"Липсва: {CLIENT}")

    ACCOUNTS.mkdir(exist_ok=True)

    flow = InstalledAppFlow.from_client_secrets_file(
        str(CLIENT), SCOPES
    )

    credentials = flow.run_local_server(
        host="localhost",
        port=0,
        open_browser=True,
        authorization_prompt_message=(
            "Отвори този адрес за Google удостоверяване: {url}"
        ),
        prompt="select_account",
        access_type="offline",
        include_granted_scopes="true"
    )

    service = build("gmail", "v1", credentials=credentials)
    profile = service.users().getProfile(userId="me").execute()
    email = profile["emailAddress"].lower()

    safe_email = re.sub(r"[^a-z0-9@._-]", "_", email)
    destination = ACCOUNTS / f"{safe_email}.json"

    if destination.exists():
        answer = input(
            f"Акаунтът {email} съществува. Замени токена? [y/N]: "
        ).strip().lower()
        if answer != "y":
            print("Съществуващият токен е запазен.")
            return

    destination.write_text(
        credentials.to_json(), encoding="utf-8"
    )
    try:
        os.chmod(destination, 0o600)
    except OSError:
        pass

    print(f"Добавен Google акаунт: {email}")
    print(f"Токен: {destination}")
    print("Не публикувай този файл и не го добавяй в Git.")

if __name__ == "__main__":
    main()

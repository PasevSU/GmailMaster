import os
import sys
import yaml  # <-- Добавяме това
from datetime import datetime, timezone
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

TOKEN_FILE = 'gmail_token.json'
FILTERS_FILE = 'filters.yaml'  # <-- Променяме разширението
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
OUTPUT_MD = 'gmail_table.md'
OUTPUT_HTML = 'gmail_table.html'
MAX_EMAILS = 100

def load_filters():
    """Зарежда филтрите от YAML файла."""
    if not os.path.exists(FILTERS_FILE):
        print(f"Внимание: {FILTERS_FILE} не е намерен. Използват се настройки по подразбиране.", file=sys.stderr)
        return {}
    with open(FILTERS_FILE, 'r', encoding='utf-8') as f:
        # Четем YAML съдържанието
        data = yaml.safe_load(f)
        return data if data else {}

def get_service():
    if not os.path.exists(TOKEN_FILE):
        raise FileNotFoundError(f"Не е намерен файл: {TOKEN_FILE}. Моля, стартирайте gmail_auth.py първо.")
    creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
    return build('gmail', 'v1', credentials=creds)

def build_gmail_query(filters):
    """Изгражда Gmail заявка (q параметър) въз основа на филтрите."""
    query_parts = []

    if filters.get('unread_only'):
        query_parts.append('is:unread')

    if filters.get('has_attachment'):
        query_parts.append('has:attachment')

    if filters.get('subject_contains'):
        query_parts.append(f'subject:"{filters["subject_contains"]}"')

    if filters.get('from_contains'):
        query_parts.append(f'from:"{filters["from_contains"]}"')

    if filters.get('label'):
        query_parts.append(f'label:{filters["label"]}')

    # Филтър за дата
    date_range = filters.get('date_range', {})
    if date_range and date_range.get('from'):
        query_parts.append(f'after:{date_range["from"]}')
    if date_range and date_range.get('to'):
        query_parts.append(f'before:{date_range["to"]}')

    return ' '.join(query_parts)

def get_emails(service, max_results, filters):
    """Извлича имейли, използвайки Gmail заявката."""
    try:
        query = build_gmail_query(filters)
        print(f"Gmail заявка: {query if query else '(няма филтри)'}", file=sys.stderr)

        results = service.users().messages().list(userId='me', q=query, maxResults=max_results).execute()
        return results.get('messages', [])
    except Exception as e:
        print(f"Грешка: {e}", file=sys.stderr)
        return []

def get_email_details(service, message_id):
    try:
        msg = service.users().messages().get(
            userId='me',
            id=message_id,
            format='metadata',
            metadataHeaders=['Date', 'From', 'To', 'Cc', 'Bcc', 'Subject']
        ).execute()
        headers = msg.get('payload', {}).get('headers', [])
        details = {'from': '', 'to': '', 'cc': '', 'bcc': '', 'subject': '', 'date': ''}
        for h in headers:
            name = h['name'].lower()
            if name in details:
                details[name] = h['value']

        try:
            date_str = details.get('date', '').split(' (')[0]
            details['date_obj'] = datetime.strptime(date_str, '%a, %d %b %Y %H:%M:%S %z')
        except Exception:
            details['date_obj'] = datetime.now(timezone.utc)

        details['search_string'] = " ".join([
            details.get('from', ''), details.get('to', ''),
            details.get('cc', ''), details.get('bcc', ''),
            details.get('subject', '')
        ]).lower()

        return details
    except Exception as e:
        print(f"Грешка при имейл {message_id}: {e}", file=sys.stderr)
        return None

def apply_python_filters(details, filters):
    """Прилага филтри, които не могат да бъдат направени директно в Gmail API."""
    domains = filters.get('domains', [])
    if domains:
        matched = False
        for domain in domains:
            if domain and domain.lower() in details['search_string']:
                matched = True
                break
        if not matched:
            return False
    return True

def generate_table(emails_data):
    emails_data.sort(key=lambda x: x['date_obj'])

    md_lines = ["| Дата на изпращане | От | До | Цц | Тема |", "|---|---|---|---|---|"]
    html_lines = [
        "<table border='1' style='border-collapse: collapse; width: 100%; font-family: sans-serif;'>",
        "<thead style='background-color: #2c3e50; color: white;'><tr><th>Дата на изпращане</th><th>От</th><th>До</th><th>Цц</th><th>Тема</th></tr></thead>",
        "<tbody>"
    ]

    for data in emails_data:
        date_clean = data.get('date', '').replace('|', '\\|').replace('\n', ' ')
        from_clean = data.get('from', '').replace('|', '\\|').replace('\n', ' ')
        to_clean = data.get('to', '').replace('|', '\\|').replace('\n', ' ')
        cc_clean = data.get('cc', '').replace('|', '\\|').replace('\n', ' ')
        subject_clean = data.get('subject', '').replace('|', '\\|').replace('\n', ' ')

        md_lines.append(f"| {date_clean} | {from_clean} | {to_clean} | {cc_clean} | {subject_clean} |")
        html_lines.append(f"<tr><td>{data.get('date', '')}</td><td>{data.get('from', '')}</td><td>{data.get('to', '')}</td><td>{data.get('cc', '')}</td><td>{data.get('subject', '')}</td></tr>")

    html_lines.append("</tbody></table>")

    with open(OUTPUT_MD, 'w', encoding='utf-8') as f:
        f.write('\n'.join(md_lines))
    with open(OUTPUT_HTML, 'w', encoding='utf-8') as f:
        f.write('\n'.join(html_lines))

def main():
    try:
        filters = load_filters()
        service = get_service()

        messages = get_emails(service, MAX_EMAILS, filters)

        filtered_emails = []
        for msg in messages:
            details = get_email_details(service, msg['id'])
            if details and apply_python_filters(details, filters):
                filtered_emails.append(details)

        generate_table(filtered_emails)
        print(f"Успешно генерирани таблици за {len(filtered_emails)} имейла (от общо {len(messages)} изтеглени).")

    except Exception as e:
        print(f"Грешка: {e}", file=sys.stderr)

if __name__ == '__main__':
    main()

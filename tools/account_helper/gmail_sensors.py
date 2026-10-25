import json
import os
import sys
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build

# Пътят до новия токен, който току-що създадохте
TOKEN_FILE = 'gmail_token.json'
SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

def get_service():
    # Зареждаме токена
    if not os.path.exists(TOKEN_FILE):
        raise FileNotFoundError(f"Не е намерен файл: {TOKEN_FILE}. Моля, стартирайте gmail_auth.py първо.")
    
    creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    
    # Ако токенът е изтекъл, го опресняваме
    if creds.expired and creds.refresh_token:
        creds.refresh(Request())
        # Запазваме обновения токен
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())
            
    return build('gmail', 'v1', credentials=creds)

def get_unread_count(service, label_name):
    # Търсим имейли с даден етикет и статус "непрочетено"
    query = f'label:{label_name} is:unread'
    try:
        results = service.users().messages().list(userId='me', q=query).execute()
        return results.get('resultSizeEstimate', 0)
    except Exception as e:
        return 0

def main():
    try:
        service = get_service()
        
        # Тук можете да смените имената на етикетите с тези, които реално използвате в Gmail
        categories = {
            "Финанси": get_unread_count(service, "Finance"),
            "Пратки": get_unread_count(service, "Delivery"),
            "Изискващи внимание": get_unread_count(service, "Important")
        }
        
        # Изчисляваме общия брой
        categories["total"] = sum(categories.values())
        
        # Отпечатваме JSON за Home Assistant
        print(json.dumps(categories))
        
    except Exception as e:
        # При грешка връщаме JSON с нули и съобщение за грешка
        print(json.dumps({"error": str(e), "total": 0, "Финанси": 0, "Пратки": 0, "Изискващи внимание": 0}))

if __name__ == '__main__':
    main()
from __future__ import annotations

import os


def send_telegram_message(chat_id: int, text: str, session_id: str) -> None:
    token = os.getenv('TELEGRAM_BOT_TOKEN', '')
    if not token:
        return
    import httpx
    keyboard = {
        'inline_keyboard': [[
            {'text': 'Подтвердить ✅', 'callback_data': f'2fa:login:approve:{session_id.replace("-", "")}'},
            {'text': 'Отклонить ❌', 'callback_data': f'2fa:login:deny:{session_id.replace("-", "")}'},
        ]]
    }
    with httpx.Client(base_url=f'https://api.telegram.org/bot{token}', timeout=10) as client:
        response = client.post('/sendMessage', json={'chat_id': chat_id, 'text': text, 'reply_markup': keyboard})
        response.raise_for_status()



def send_telegram_settings_message(chat_id: int, action: str, pending_id: str) -> None:
    token = os.getenv('TELEGRAM_BOT_TOKEN', '')
    if not token:
        return
    import httpx
    action_ru = 'включить' if action == 'enable' else 'выключить'
    keyboard = {
        'inline_keyboard': [[
            {'text': 'Подтвердить ✅', 'callback_data': f'2fa:set:approve:{pending_id}'},
            {'text': 'Отклонить ❌', 'callback_data': f'2fa:set:deny:{pending_id}'},
        ]]
    }
    text = f'🔐 Запрос на изменение 2FA\n\nПодтвердите действие: {action_ru} двухфакторную аутентификацию через Telegram.'
    with httpx.Client(base_url=f'https://api.telegram.org/bot{token}', timeout=10) as client:
        response = client.post('/sendMessage', json={'chat_id': chat_id, 'text': text, 'reply_markup': keyboard})
        response.raise_for_status()

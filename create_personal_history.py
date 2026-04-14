from supabase import create_client

url = 'https://qjgzhtkpwamounnpgepr.supabase.co'
key = 'sb_publishable_WV7YnhP_OAWYx8gQjOmG1Q_7GdKOVlV'
supabase = create_client(url, key)

# Создаём таблицу personal_history
try:
    supabase.table('personal_history').create({
        'user_id': 'bigint',
        'chunk_name': 'text',
        'amount': 'numeric',
        'action_type': 'text',  # 'give' - выдача, 'take' - вычет
        'created_at': 'timestamp'
    })
    print('Таблица personal_history создана!')
except Exception as e:
    print(f'Ошибка: {e}')
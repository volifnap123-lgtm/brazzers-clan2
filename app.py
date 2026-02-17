import os
from flask import Flask, render_template, request, redirect, session, make_response
from supabase import create_client
import bcrypt
from datetime import datetime
import io
import csv

app = Flask(__name__)
app.secret_key = 'brazzers_secret_2026_strong'

# Инициализация Supabase
SUPABASE_URL = os.environ['SUPABASE_URL']
SUPABASE_KEY = os.environ['SUPABASE_ANON_KEY']
supabase = create_client(SUPABASE_URL, SUPABASE_KEY)

def cleanup_old_records():
    tables_and_columns = [
        ('stats', 'updated_at'),
        ('audit_log', 'timestamp'),
        ('change_requests', 'created_at'),
        ('news', 'created_at'),
        ('issued_chunks', 'issued_at'),
        ('chunk_requests', 'created_at')
    ]
    one_year_ago = datetime.now().replace(year=datetime.now().year - 1).isoformat()
    for table, col in tables_and_columns:
        supabase.table(table).delete().lt(col, one_year_ago).execute()

def log_action(admin_id, action, details):
    try:
        supabase.table('audit_log').insert({
            'admin_id': admin_id,
            'action': action,
            'details': str(details)
        }).execute()
    except Exception as e:
        print(f"Ошибка логирования: {e}")

@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login']
        password = request.form['password']
        user_data = supabase.table('users').select('*').eq('login', login_input).execute()
        user = user_data.data[0] if user_data.data else None
        
        if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
            session.permanent = True
            app.permanent_session_lifetime = 600
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['username'] = user['username']
            
            rejected_data = supabase.table('change_requests') \
                .select('reason') \
                .eq('user_id', user['id']) \
                .eq('status', 'rejected') \
                .order('created_at', desc=True) \
                .limit(1) \
                .execute()
            rejected = rejected_data.data[0] if rejected_data.data else None
            
            if rejected:
                session['reject_reason'] = rejected['reason']
            else:
                session.pop('reject_reason', None)
                
            return redirect('/dashboard')
        else:
            return render_template('login.html', error="Неверный логин или пароль")
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    
    user_data = supabase.table('users').select('*').eq('id', session['user_id']).execute()
    user = user_data.data[0] if user_data.data else None
    
    # Получаем историю статистики (только для отображения)
    stats_history = supabase.table('stats') \
        .select('chunk1,chunk2,chunk3,chunk4,chunk5,chunk6,chunk7,chunk8,vr1,vr2,vr3,core,updated_at') \
        .eq('user_id', session['user_id']) \
        .order('updated_at', desc=True) \
        .limit(10) \
        .execute()
    stats_rows = stats_history.data if stats_history.data else []

    # Рассчитываем ОБЩЕЕ количество как СУММУ ВСЕХ записей
    chunks = ['chunk1','chunk2','chunk3','chunk4','chunk5','chunk6','chunk7','chunk8','vr1','vr2','vr3','core']
    full_stats = supabase.table('stats') \
        .select('chunk1,chunk2,chunk3,chunk4,chunk5,chunk6,chunk7,chunk8,vr1,vr2,vr3,core') \
        .eq('user_id', session['user_id']) \
        .execute()
    total = {k: sum(row.get(k, 0) for row in full_stats.data) if full_stats.data else 0 for k in chunks}

    # Рассчитываем 6б13
    issued_counts = {}
    for chunk in chunks:
        count_data = supabase.table('issued_chunks') \
            .select('*', count='exact') \
            .eq('user_id', session['user_id']) \
            .eq('chunk_name', chunk) \
            .execute()
        issued_counts[chunk] = count_data.count if hasattr(count_data, 'count') else len(count_data.data)
    six_b13 = min(issued_counts.values()) if issued_counts else 0

    # Рассчитываем отданные проценты
    given_data = supabase.table('transfers') \
        .select('amount') \
        .eq('from_user_id', session['user_id']) \
        .execute()
    given = sum(row['amount'] for row in given_data.data) if given_data.data else 0

    # Загружаем всех пользователей
    all_users_data = supabase.table('users').select('id,username,login,role').execute()
    all_users_dict = {u['id']: u for u in all_users_data.data} if all_users_data.data else {}

    # Считаем сумму по всем игрокам для общака
    all_users_stats = {}
    stats_all = supabase.table('stats').select('*').execute()
    for s in stats_all.data or []:
        uid = s['user_id']
        if uid not in all_users_stats:
            all_users_stats[uid] = {k: 0 for k in chunks}
        for k in chunks:
            all_users_stats[uid][k] += s.get(k, 0)

    # Считаем 6б13 для всех
    all_users_six_b13 = {}
    for uid in all_users_dict:
        issued_counts_user = {}
        for chunk in chunks:
            count_data = supabase.table('issued_chunks') \
                .select('*', count='exact') \
                .eq('user_id', uid) \
                .eq('chunk_name', chunk) \
                .execute()
            issued_counts_user[chunk] = count_data.count if hasattr(count_data, 'count') else len(count_data.data)
        all_users_six_b13[uid] = min(issued_counts_user.values()) if issued_counts_user else 0

    all_users = []
    for uid, user_info in all_users_dict.items():
        s = all_users_stats.get(uid, {k: 0 for k in chunks})
        all_users.append({
            'username': user_info['username'],
            'chunk1': s['chunk1'], 'chunk2': s['chunk2'], 'chunk3': s['chunk3'], 'chunk4': s['chunk4'],
            'chunk5': s['chunk5'], 'chunk6': s['chunk6'], 'chunk7': s['chunk7'], 'chunk8': s['chunk8'],
            'vr1': s['vr1'], 'vr2': s['vr2'], 'vr3': s['vr3'], 'core': s['core'],
            'six_b13': all_users_six_b13.get(uid, 0)
        })

    # Топ-5
    top5 = []
    for u in all_users:
        total_val = sum(u[k] for k in chunks)
        top5.append({'username': u['username'], 'total': round(total_val, 1)})
    top5 = sorted(top5, key=lambda x: x['total'], reverse=True)[:5]

    # Новости
    news_data = supabase.table('news').select('*').order('created_at', desc=True).execute()
    news_with_authors = []
    for n in news_data.data or []:
        author = all_users_dict.get(n['author_id'], {'username': 'Unknown'})
        news_with_authors.append({**n, 'author_name': author['username']})

    # === ОБЩАК: СУММА ПО ВСЕМ ПОЛЬЗОВАТЕЛЯМ ===
    common_fund = {chunk: 0.0 for chunk in chunks}
    for uid, stats in all_users_stats.items():
        for chunk in chunks:
            common_fund[chunk] += stats[chunk]

    return render_template('user_dashboard.html', user=user, stats_rows=stats_rows, total=total, 
                          six_b13=six_b13, given_percent=given,
                          all_users=all_users, top5=top5, news=news_with_authors, common_fund=common_fund)

@app.route('/admin-panel')
def admin_panel():
    if 'role' not in session or session['role'] not in ('admin', 'admin2'):
        return redirect('/')
    
    users_data = supabase.table('users').select('id,username,login').execute()
    users = users_data.data if users_data else []
    
    chunks = ['chunk1', 'chunk2', 'chunk3', 'chunk4', 'chunk5', 'chunk6', 'chunk7', 'chunk8', 'vr1', 'vr2', 'vr3', 'core']
    
    # Загружаем общак
    common_fund = {}
    try:
        common_fund_data = supabase.table('common_fund').select('chunk_name,amount').execute()
        if common_fund_data.data:
            common_fund = {row['chunk_name']: row['amount'] for row in common_fund_data.data}
    except Exception as e:
        print(f"Ошибка загрузки общака: {e}")
    
    # Загружаем остатки С БЕЗОПАСНОЙ ОБРАБОТКОЙ
    remainder = {}
    try:
        remainder_data = supabase.table('remainder').select('chunk_name,amount').execute()
        if remainder_data.data and hasattr(remainder_data, 'data'):
            remainder = {row['chunk_name']: float(row['amount']) for row in remainder_data.data}
    except Exception as e:
        print(f"Ошибка загрузки остатков (таблица может быть пустой или отсутствовать): {e}")
        remainder = {chunk: 0.0 for chunk in chunks}  # Гарантируем передачу всех ключей
    
    # Загружаем запросы
    chunk_requests = []
    try:
        chunk_requests_data = supabase.table('chunk_requests').select('*').eq('status', 'pending').execute()
        for r in chunk_requests_data.data or []:
            user_info = next((u for u in users if u['id'] == r['user_id']), {'username': 'Unknown'})
            chunk_requests.append({**r, 'username': user_info['username']})
    except Exception as e:
        print(f"Ошибка загрузки запросов: {e}")
    
    return render_template(
        'admin_panel.html',
        users=users,
        chunks=chunks,
        common_fund=common_fund,
        remainder=remainder,  # ВСЕГДА передаём, даже если пустой
        chunk_requests=chunk_requests
    )

@app.route('/tech-mode')
def tech_mode():
    if session.get('role') != 'admin2':
        return redirect('/admin-panel')
    
    logs_data = supabase.table('audit_log').select('*').order('timestamp', desc=True).limit(50).execute()
    logs = logs_data.data if logs_data.data else []
    
    users_data = supabase.table('users').select('id,username,login,role').execute()
    users = users_data.data if users_data.data else []
    
    requests_data = supabase.table('change_requests') \
        .select('*') \
        .eq('status', 'pending') \
        .order('created_at', desc=True) \
        .execute()
    requests = []
    for r in requests_data.data or []:
        user_info = next((u for u in users if u['id'] == r['user_id']), {'username': 'Unknown', 'login': 'unknown'})
        requests.append({**r, 'user_name': user_info['username'], 'user_login': user_info['login']})
    
    return render_template('tech_mode.html', logs=logs, users=users, db_size=0, requests=requests)

@app.route('/api/export-db')
def export_db():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    
    output = io.StringIO()
    writer = csv.writer(output)
    
    tables = ['users', 'stats', 'transfers', 'common_fund', 'audit_log', 'change_requests', 'news', 'issued_chunks', 'chunk_requests']
    for table in tables:
        writer.writerow([f'=== TABLE: {table} ==='])
        data = supabase.table(table).select('*').execute()
        if data.data:
            columns = list(data.data[0].keys())
            writer.writerow(columns)
            for row in data.data:
                writer.writerow([row.get(col, '') for col in columns])
        writer.writerow([])
    
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=brazzers_full_backup.csv"
    response.headers["Content-type"] = "text/csv"
    return response

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/api/give-percent-single', methods=['POST'])
def api_give_percent_single():
    if 'role' not in session:
        return redirect('/')
    cleanup_old_records()
    user_id = request.form['user_id']
    chunks = ['chunk1', 'chunk2', 'chunk3', 'chunk4', 'chunk5', 'chunk6', 'chunk7', 'chunk8', 'vr1', 'vr2', 'vr3', 'core']
    values = {c: float(request.form.get(c, 0)) for c in chunks}
    values['user_id'] = user_id
    supabase.table('stats').insert(values).execute()
    log_action(session['user_id'], 'give_percent_single', f"user={user_id}, {values}")
    return redirect('/admin-panel')

@app.route('/api/give-percent-multiple', methods=['POST'])
def api_give_percent_multiple():
    if 'role' not in session:
        return redirect('/')
    cleanup_old_records()
    user_ids = request.form.getlist('user_ids')
    chunk = request.form['chunk']
    amount_per = round(100.0 / len(user_ids), 1)
    
    # Вычисляем остаток
    distributed_total = amount_per * len(user_ids)
    remainder_amount = round(100.0 - distributed_total, 1)
    
    # Выдаём проценты игрокам
    for uid in user_ids:
        values = {k: 0 for k in ['chunk1','chunk2','chunk3','chunk4','chunk5','chunk6','chunk7','chunk8','vr1','vr2','vr3','core']}
        values[chunk] = amount_per
        values['user_id'] = uid
        supabase.table('stats').insert(values).execute()
    
    # Добавляем остаток в таблицу remainder
    if abs(remainder_amount) > 0.01:
        remainder_data = supabase.table('remainder').select('amount').eq('chunk_name', chunk).execute()
        current_remainder = remainder_data.data[0]['amount'] if remainder_data.data else 0
        new_remainder = current_remainder + remainder_amount
        if remainder_data.data:
            supabase.table('remainder').update({'amount': new_remainder}).eq('chunk_name', chunk).execute()
        else:
            supabase.table('remainder').insert({'chunk_name': chunk, 'amount': new_remainder}).execute()
    
    log_action(session['user_id'], 'give_percent_multi', f"chunk={chunk}, users={user_ids}, each={amount_per}, remainder={remainder_amount}")
    return redirect('/admin-panel')

@app.route('/api/transfer-percent', methods=['POST'])
def api_transfer_percent():
    if 'role' not in session:
        return redirect('/')
    cleanup_old_records()
    from_id = request.form['from_user']
    to_id = request.form['to_user']
    chunk = request.form['chunk']
    amount = float(request.form['amount'])
    
    # Проверяем баланс отправителя
    from_stats_all = supabase.table('stats').select(chunk).eq('user_id', from_id).execute()
    balance = sum(row.get(chunk, 0) for row in from_stats_all.data) if from_stats_all.data else 0
    
    if balance < amount:
        return redirect('/admin-panel')
    
    # Создаём запись с отрицательным значением для отправителя
    from_values = {k: 0 for k in ['chunk1','chunk2','chunk3','chunk4','chunk5','chunk6','chunk7','chunk8','vr1','vr2','vr3','core']}
    from_values[chunk] = -amount
    from_values['user_id'] = from_id
    supabase.table('stats').insert(from_values).execute()
    
    # Создаём запись с положительным значением для получателя
    to_values = {k: 0 for k in ['chunk1','chunk2','chunk3','chunk4','chunk5','chunk6','chunk7','chunk8','vr1','vr2','vr3','core']}
    to_values[chunk] = amount
    to_values['user_id'] = to_id
    supabase.table('stats').insert(to_values).execute()
    
    # Логируем передачу
    supabase.table('transfers').insert({
        'from_user_id': from_id,
        'to_user_id': to_id,
        'chunk_name': chunk,
        'amount': amount
    }).execute()
    
    log_action(session['user_id'], 'transfer', f"{from_id}->{to_id}, {chunk}={amount}")
    return redirect('/admin-panel')

# Запрос на выдачу куска
@app.route('/api/request-chunk', methods=['POST'])
def api_request_chunk():
    if 'user_id' not in session:
        return redirect('/dashboard')
    cleanup_old_records()
    user_id = session['user_id']
    chunk = request.form['chunk']
    
    stats_data = supabase.table('stats').select(chunk).eq('user_id', user_id).execute()
    current_balance = sum(row.get(chunk, 0) for row in stats_data.data) if stats_data.data else 0
    
    if current_balance >= 100:
        values = {k: 0 for k in ['chunk1','chunk2','chunk3','chunk4','chunk5','chunk6','chunk7','chunk8','vr1','vr2','vr3','core']}
        values[chunk] = -100.0
        values['user_id'] = user_id
        supabase.table('stats').insert(values).execute()
        
        supabase.table('chunk_requests').insert({
            'user_id': user_id,
            'chunk_name': chunk,
            'status': 'pending'
        }).execute()
        
        log_action(user_id, 'chunk_request_created', f"user={user_id}, chunk={chunk}, status=pending")
    
    return redirect('/dashboard')

# Подтвердить запрос
@app.route('/api/approve-chunk-request', methods=['POST'])
def api_approve_chunk_request():
    if 'role' not in session or session['role'] not in ('admin', 'admin2'):
        return redirect('/admin-panel')
    cleanup_old_records()
    request_id = request.form['request_id']
    
    req_data = supabase.table('chunk_requests').select('*').eq('id', request_id).execute()
    req = req_data.data[0] if req_data.data else None
    
    if req:
        user_id = req['user_id']
        chunk = req['chunk_name']
        
        supabase.table('issued_chunks').insert({
            'user_id': user_id,
            'chunk_name': chunk
        }).execute()
        
        supabase.table('chunk_requests').update({'status': 'approved'}).eq('id', request_id).execute()
        
        log_action(session['user_id'], 'chunk_request_approved', f"user={user_id}, chunk={chunk}, status=approved")
    
    return redirect('/admin-panel')

# Отклонить запрос
@app.route('/api/reject-chunk-request', methods=['POST'])
def api_reject_chunk_request():
    if 'role' not in session or session['role'] not in ('admin', 'admin2'):
        return redirect('/admin-panel')
    cleanup_old_records()
    request_id = request.form['request_id']
    reason = request.form.get('reason', '')
    
    req_data = supabase.table('chunk_requests').select('*').eq('id', request_id).execute()
    req = req_data.data[0] if req_data.data else None
    
    if req:
        user_id = req['user_id']
        chunk = req['chunk_name']
        
        values = {k: 0 for k in ['chunk1','chunk2','chunk3','chunk4','chunk5','chunk6','chunk7','chunk8','vr1','vr2','vr3','core']}
        values[chunk] = 100.0
        values['user_id'] = user_id
        supabase.table('stats').insert(values).execute()
        
        supabase.table('chunk_requests').update({'status': 'rejected', 'reason': reason}).eq('id', request_id).execute()
        
        log_action(session['user_id'], 'chunk_request_rejected', f"user={user_id}, chunk={chunk}, status=rejected, reason={reason}")
    
    return redirect('/admin-panel')

@app.route('/api/common-add', methods=['POST'])
def api_common_add():
    if 'role' not in session:
        return redirect('/')
    cleanup_old_records()
    chunk = request.form['chunk']
    amount = float(request.form['amount'])
    fund_data = supabase.table('common_fund').select('amount').eq('chunk_name', chunk).execute()
    current = fund_data.data[0]['amount'] if fund_data.data else 0
    supabase.table('common_fund').update({'amount': current + amount}).eq('chunk_name', chunk).execute()
    log_action(session['user_id'], 'common_add', f"{chunk}+{amount}")
    return redirect('/admin-panel')

@app.route('/api/common-remove', methods=['POST'])
def api_common_remove():
    if 'role' not in session:
        return redirect('/')
    cleanup_old_records()
    chunk = request.form['chunk']
    amount = float(request.form['amount'])
    fund_data = supabase.table('common_fund').select('amount').eq('chunk_name', chunk).execute()
    current = fund_data.data[0]['amount'] if fund_data.data else 0
    supabase.table('common_fund').update({'amount': current - amount}).eq('chunk_name', chunk).execute()
    log_action(session['user_id'], 'common_remove', f"{chunk}-{amount}")
    return redirect('/admin-panel')

@app.route('/api/remove-admin', methods=['POST'])
def api_remove_admin():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    supabase.table('users').update({'role': 'user'}).eq('id', user_id).execute()
    log_action(session['user_id'], 'remove_admin', f"user={user_id}")
    return redirect('/tech-mode')

@app.route('/api/promote-to-admin', methods=['POST'])
def api_promote_to_admin():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    supabase.table('users').update({'role': 'admin'}).eq('id', user_id).eq('role', 'user').execute()
    log_action(session['user_id'], 'promote_to_admin', f"user_id={user_id}")
    return redirect('/tech-mode')

@app.route('/api/create-user', methods=['POST'])
def api_create_user():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    username = request.form['username']
    login = request.form['login']
    password = request.form['password']
    pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')
    try:
        supabase.table('users').insert({
            'username': username,
            'login': login,
            'password_hash': pwd_hash,
            'role': 'user'
        }).execute()
        log_action(session['user_id'], 'create_user', f"login={login}, username={username}")
    except Exception:
        pass
    return redirect('/tech-mode')

@app.route('/api/delete-user', methods=['POST'])
def api_delete_user():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    supabase.table('users').delete().eq('id', user_id).execute()
    supabase.table('stats').delete().eq('user_id', user_id).execute()
    # Удаляем записи из issued_chunks
    issued_data = supabase.table('issued_chunks').select('id').eq('user_id', user_id).execute()
    for item in issued_data.data or []:
        supabase.table('issued_chunks').delete().eq('id', item['id']).execute()
    # Удаляем передачи
    transfers_out = supabase.table('transfers').select('id').eq('from_user_id', user_id).execute()
    for t in transfers_out.data or []:
        supabase.table('transfers').delete().eq('id', t['id']).execute()
    transfers_in = supabase.table('transfers').select('id').eq('to_user_id', user_id).execute()
    for t in transfers_in.data or []:
        supabase.table('transfers').delete().eq('id', t['id']).execute()
    log_action(session['user_id'], 'delete_user', f"user_id={user_id}")
    return redirect('/tech-mode')

@app.route('/api/change-login', methods=['POST'])
def api_change_login():
    if 'user_id' not in session:
        return redirect('/')
    cleanup_old_records()
    new_login = request.form['new_login']
    try:
        supabase.table('users').update({'login': new_login}).eq('id', session['user_id']).execute()
    except Exception:
        pass
    return redirect('/dashboard')

@app.route('/api/change-password', methods=['POST'])
def api_change_password():
    if 'user_id' not in session:
        return redirect('/')
    cleanup_old_records()
    new_pass = request.form['new_password']
    if not new_pass or len(new_pass) < 4:
        return redirect('/dashboard')
    
    pwd_hash = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode('utf-8')
    try:
        supabase.table('users').update({'password_hash': pwd_hash}).eq('id', session['user_id']).execute()
        session.clear()
        return redirect('/')
    except Exception as e:
        print(f"Ошибка при смене пароля: {e}")
        return redirect('/dashboard')

@app.route('/api/request-change', methods=['POST'])
def api_request_change():
    if 'user_id' not in session:
        return redirect('/')
    cleanup_old_records()
    new_login = request.form.get('new_login')
    new_password = request.form.get('new_password')
    
    insert_data = {'user_id': session['user_id']}
    if new_login:
        insert_data['new_login'] = new_login
    if new_password:
        pwd_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode('utf-8')
        insert_data['new_password_hash'] = pwd_hash
    
    insert_data['status'] = 'pending'
    supabase.table('change_requests').insert(insert_data).execute()
    details = f"login={new_login}" + (", password=***" if new_password else "")
    log_action(session['user_id'], 'request_change', details)
    return redirect('/dashboard')

@app.route('/api/approve-change', methods=['POST'])
def api_approve_change():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    request_id = request.form['request_id']
    req_data = supabase.table('change_requests').select('*').eq('id', request_id).execute()
    req = req_data.data[0] if req_data.data else None
    if req:
        update_data = {}
        if req.get('new_login'):
            update_data['login'] = req['new_login']
        if req.get('new_password_hash'):
            update_data['password_hash'] = req['new_password_hash']
        if update_data:
            supabase.table('users').update(update_data).eq('id', req['user_id']).execute()
        supabase.table('change_requests').update({'status': 'approved'}).eq('id', request_id).execute()
        log_action(session['user_id'], 'approve_change', f"request_id={request_id}, user_id={req['user_id']}")
    return redirect('/tech-mode')

@app.route('/api/reject-change', methods=['POST'])
def api_reject_change():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    request_id = request.form['request_id']
    reason = request.form['reason']
    supabase.table('change_requests').update({'status': 'rejected', 'reason': reason}).eq('id', request_id).execute()
    log_action(session['user_id'], 'reject_change', f"request_id={request_id}, reason={reason}")
    return redirect('/tech-mode')

@app.route('/api/post-news', methods=['POST'])
def api_post_news():
    if 'role' not in session or session['role'] not in ('admin', 'admin2'):
        return redirect('/')
    cleanup_old_records()
    message = request.form['message']
    try:
        supabase.table('news').insert({
            'author_id': session['user_id'],
            'message': message,
            'role': session['role']
        }).execute()
        log_action(session['user_id'], 'post_news', f"message='{message[:50]}...'")
    except Exception as e:
        print(f"Ошибка при публикации новости: {e}")
    return redirect('/admin-panel' if session['role'] == 'admin' else '/tech-mode')

@app.route('/api/admin-change-login', methods=['POST'])
def api_admin_change_login():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    new_login = request.form['new_login']
    try:
        supabase.table('users').update({'login': new_login}).eq('id', user_id).execute()
        log_action(session['user_id'], 'admin_change_login', f"user_id={user_id}, new_login={new_login}")
    except Exception:
        pass
    return redirect('/tech-mode')

@app.route('/api/admin-change-password', methods=['POST'])
def api_admin_change_password():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    new_pass = request.form['new_password']
    pwd_hash = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode('utf-8')
    try:
        supabase.table('users').update({'password_hash': pwd_hash}).eq('id', user_id).execute()
        log_action(session['user_id'], 'admin_change_password', f"user_id={user_id}")
    except:
        pass
    return redirect('/tech-mode')

@app.route('/api/clear-reject-notice')
def api_clear_reject_notice():
    session.pop('reject_reason', None)
    return redirect('/dashboard')

@app.route('/keep-alive')
def keep_alive():
    return 'OK', 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

import os
from flask import Flask, render_template, request, redirect, session, send_file, make_response
import psycopg2
from psycopg2.extras import RealDictCursor
import bcrypt
from datetime import datetime
import io
import csv

app = Flask(__name__)
app.secret_key = 'brazzers_secret_2026_strong'

DATABASE_URL = os.environ['DATABASE_URL']

def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def cleanup_old_records():
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute("DELETE FROM stats WHERE updated_at < NOW() - INTERVAL '12 months'")
            c.execute("DELETE FROM audit_log WHERE timestamp < NOW() - INTERVAL '12 months'")
            c.execute("DELETE FROM change_requests WHERE created_at < NOW() - INTERVAL '12 months'")
            c.execute("DELETE FROM news WHERE created_at < NOW() - INTERVAL '12 months'")
            conn.commit()
    finally:
        conn.close()

def log_action(admin_id, action, details):
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('INSERT INTO audit_log (admin_id, action, details) VALUES (%s, %s, %s)', (admin_id, action, str(details)))
            conn.commit()
    finally:
        conn.close()

# === LOGIN ===
@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login']
        password = request.form['password']
        conn = get_db_connection()
        try:
            with conn.cursor() as c:
                c.execute('SELECT * FROM users WHERE login = %s', (login_input,))
                user = c.fetchone()
            if user and bcrypt.checkpw(password.encode(), user['password_hash'].encode()):
                session.permanent = True
                app.permanent_session_lifetime = 600
                session['user_id'] = user['id']
                session['role'] = user['role']
                session['username'] = user['username']
                
                with conn.cursor() as c:
                    c.execute('SELECT reason FROM change_requests WHERE user_id = %s AND status = %s ORDER BY created_at DESC LIMIT 1', (user['id'], 'rejected'))
                    rejected = c.fetchone()
                if rejected:
                    session['reject_reason'] = rejected['reason']
                else:
                    session.pop('reject_reason', None)
                    
                return redirect('/dashboard')
            else:
                return render_template('login.html', error="Неверный логин или пароль")
        finally:
            conn.close()
    return render_template('login.html')

# === DASHBOARD ===
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('SELECT * FROM users WHERE id = %s', (session['user_id'],))
            user = c.fetchone()

        with conn.cursor() as c:
            c.execute('''
                SELECT 
                    COALESCE(MAX(chunk1), 0) as chunk1,
                    COALESCE(MAX(chunk2), 0) as chunk2,
                    COALESCE(MAX(chunk3), 0) as chunk3,
                    COALESCE(MAX(chunk4), 0) as chunk4,
                    COALESCE(MAX(chunk5), 0) as chunk5,
                    COALESCE(MAX(chunk6), 0) as chunk6,
                    COALESCE(MAX(chunk7), 0) as chunk7,
                    COALESCE(MAX(chunk8), 0) as chunk8,
                    COALESCE(MAX(vr1), 0) as vr1,
                    COALESCE(MAX(vr2), 0) as vr2,
                    COALESCE(MAX(vr3), 0) as vr3,
                    COALESCE(MAX(core), 0) as core
                FROM stats WHERE user_id = %s
            ''', (session['user_id'],))
            last_stats = c.fetchone()

        total = {k: last_stats[k] for k in
                 ['chunk1', 'chunk2', 'chunk3', 'chunk4', 'chunk5', 'chunk6', 'chunk7', 'chunk8', 'vr1', 'vr2', 'vr3',
                  'core']}

        with conn.cursor() as c:
            c.execute('SELECT SUM(amount) FROM transfers WHERE from_user_id = %s', (session['user_id'],))
            given = c.fetchone()['sum'] or 0

        with conn.cursor() as c:
            c.execute('''
                SELECT u.username,
                       COALESCE(MAX(s.chunk1), 0) as chunk1,
                       COALESCE(MAX(s.chunk2), 0) as chunk2,
                       COALESCE(MAX(s.vr1), 0) as vr1,
                       COALESCE(MAX(s.chunk3), 0) as chunk3,
                       COALESCE(MAX(s.chunk4), 0) as chunk4,
                       COALESCE(MAX(s.chunk5), 0) as chunk5,
                       COALESCE(MAX(s.vr2), 0) as vr2,
                       COALESCE(MAX(s.chunk6), 0) as chunk6,
                       COALESCE(MAX(s.chunk7), 0) as chunk7,
                       COALESCE(MAX(s.chunk8), 0) as chunk8,
                       COALESCE(MAX(s.vr3), 0) as vr3,
                       COALESCE(MAX(s.core), 0) as core
                FROM users u
                LEFT JOIN stats s ON u.id = s.user_id
                GROUP BY u.id, u.username
            ''')
            all_users = c.fetchall()

        with conn.cursor() as c:
            c.execute('''
                SELECT u.username,
                       COALESCE(MAX(s.chunk1) + MAX(s.chunk2) + MAX(s.chunk3) + MAX(s.chunk4) + MAX(s.chunk5) + 
                                MAX(s.chunk6) + MAX(s.chunk7) + MAX(s.chunk8) + MAX(s.vr1) + MAX(s.vr2) + MAX(s.vr3) + MAX(s.core), 0) as total
                FROM users u
                LEFT JOIN stats s ON u.id = s.user_id
                GROUP BY u.id, u.username
                ORDER BY total DESC
                LIMIT 5
            ''')
            top5_data = c.fetchall()
        top5 = [{'username': row['username'], 'total': round(row['total'], 1)} for row in top5_data]

        with conn.cursor() as c:
            c.execute('''
                SELECT n.*, u.username as author_name
                FROM news n
                JOIN users u ON n.author_id = u.id
                ORDER BY n.created_at DESC
            ''')
            news = c.fetchall()

        return render_template('user_dashboard.html', user=user, stats_rows=[last_stats], total=total, given_percent=given,
                               all_users=all_users, top5=top5, news=news)
    finally:
        conn.close()

# === ADMIN PANEL ===
@app.route('/admin-panel')
def admin_panel():
    if 'role' not in session or session['role'] not in ('admin', 'admin2'):
        return redirect('/')
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute("SELECT id, username, login FROM users")
            users = c.fetchall()
        chunks = ['chunk1', 'chunk2', 'chunk3', 'chunk4', 'chunk5', 'chunk6', 'chunk7', 'chunk8', 'vr1', 'vr2', 'vr3',
                  'core']
        with conn.cursor() as c:
            c.execute("SELECT * FROM common_fund")
            common_fund = {row['chunk_name']: row['amount'] for row in c.fetchall()}
        return render_template('admin_panel.html', users=users, chunks=chunks, common_fund=common_fund)
    finally:
        conn.close()

# === TECH MODE ===
@app.route('/tech-mode')
def tech_mode():
    if session.get('role') != 'admin2':
        return redirect('/admin-panel')
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 50")
            logs = c.fetchall()
            c.execute("SELECT id, username, login, role FROM users")
            users = c.fetchall()
            c.execute('''
                SELECT cr.*, u.username as user_name, u.login as user_login
                FROM change_requests cr
                JOIN users u ON cr.user_id = u.id
                WHERE cr.status = 'pending'
                ORDER BY cr.created_at DESC
            ''')
            requests = c.fetchall()
        
        db_size = 0  # PostgreSQL size не нужен
        return render_template('tech_mode.html', logs=logs, users=users, db_size=db_size, requests=requests)
    finally:
        conn.close()

# === EXPORT DATABASE TO CSV (EXCEL-COMPATIBLE) ===
@app.route('/api/export-db')
def export_db():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    
    conn = get_db_connection()
    output = io.StringIO()
    writer = csv.writer(output)

    tables = ['users', 'stats', 'transfers', 'common_fund', 'audit_log', 'change_requests', 'news']
    for table in tables:
        writer.writerow([f'=== TABLE: {table} ==='])
        with conn.cursor() as c:
            c.execute(f"SELECT * FROM {table}")
            columns = [desc[0] for desc in c.description]
            writer.writerow(columns)
            rows = c.fetchall()
            for row in rows:
                writer.writerow(row)
        writer.writerow([])  # пустая строка между таблицами

    conn.close()

    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = "attachment; filename=brazzers_full_backup.csv"
    response.headers["Content-type"] = "text/csv"
    return response

# === LOGOUT ===
@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

# === API FUNCTIONS ===

@app.route('/api/give-percent-single', methods=['POST'])
def api_give_percent_single():
    if 'role' not in session:
        return redirect('/')
    cleanup_old_records()
    user_id = request.form['user_id']
    chunks = ['chunk1', 'chunk2', 'chunk3', 'chunk4', 'chunk5', 'chunk6', 'chunk7', 'chunk8', 'vr1', 'vr2', 'vr3',
              'core']
    values = {c: float(request.form.get(c, 0)) for c in chunks}
    conn = get_db_connection()
    try:
        cols = ', '.join(chunks)
        placeholders = ', '.join(['%s'] * len(chunks))
        query = f'INSERT INTO stats (user_id, {cols}) VALUES (%s, {placeholders})'
        with conn.cursor() as c:
            c.execute(query, [user_id] + [values[c] for c in chunks])
            conn.commit()
            log_action(session['user_id'], 'give_percent_single', f"user={user_id}, {values}")
    finally:
        conn.close()
    return redirect('/admin-panel')

@app.route('/api/give-percent-multiple', methods=['POST'])
def api_give_percent_multiple():
    if 'role' not in session:
        return redirect('/')
    cleanup_old_records()
    user_ids = request.form.getlist('user_ids')
    chunk = request.form['chunk']
    amount_per = round(100.0 / len(user_ids), 1)
    conn = get_db_connection()
    try:
        for uid in user_ids:
            with conn.cursor() as c:
                c.execute(f'SELECT {chunk} FROM stats WHERE user_id = %s ORDER BY updated_at DESC LIMIT 1', (uid,))
                last = c.fetchone()
                current = last[chunk] if last else 0
                new_val = current + amount_per
                c.execute(f'INSERT INTO stats (user_id, {chunk}) VALUES (%s, %s)', (uid, new_val))
        conn.commit()
        log_action(session['user_id'], 'give_percent_multi', f"chunk={chunk}, users={user_ids}, each={amount_per}")
    finally:
        conn.close()
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
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute(f'SELECT id, {chunk} FROM stats WHERE user_id = %s ORDER BY updated_at DESC LIMIT 1', (from_id,))
            last_from = c.fetchone()
        if not last_from or last_from[chunk] < amount:
            return redirect('/admin-panel')
        
        new_from = last_from[chunk] - amount
        with conn.cursor() as c:
            c.execute(f'UPDATE stats SET {chunk} = %s WHERE id = %s', (new_from, last_from['id']))
        
        with conn.cursor() as c:
            c.execute(f'SELECT id, {chunk} FROM stats WHERE user_id = %s ORDER BY updated_at DESC LIMIT 1', (to_id,))
            last_to = c.fetchone()
        if last_to:
            new_to = last_to[chunk] + amount
            with conn.cursor() as c:
                c.execute(f'UPDATE stats SET {chunk} = %s WHERE id = %s', (new_to, last_to['id']))
        else:
            with conn.cursor() as c:
                c.execute(f'INSERT INTO stats (user_id, {chunk}) VALUES (%s, %s)', (to_id, amount))
        
        with conn.cursor() as c:
            c.execute('INSERT INTO transfers (from_user_id, to_user_id, chunk_name, amount) VALUES (%s, %s, %s, %s)',
                      (from_id, to_id, chunk, amount))
        conn.commit()
        log_action(session['user_id'], 'transfer', f"{from_id}->{to_id}, {chunk}={amount}")
    finally:
        conn.close()
    return redirect('/admin-panel')

@app.route('/api/issue-chunk', methods=['POST'])
def api_issue_chunk():
    if 'role' not in session:
        return redirect('/')
    cleanup_old_records()
    user_id = request.form['user_id']
    chunk = request.form['chunk']
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute(f'SELECT id, {chunk} FROM stats WHERE user_id = %s ORDER BY updated_at DESC LIMIT 1', (user_id,))
            last = c.fetchone()
        current = last[chunk] if last else 0
        new_val = current - 100.0
        if new_val < 0: new_val = 0
        if last:
            with conn.cursor() as c:
                c.execute(f'UPDATE stats SET {chunk} = %s WHERE id = %s', (new_val, last['id']))
        else:
            with conn.cursor() as c:
                c.execute(f'INSERT INTO stats (user_id, {chunk}) VALUES (%s, %s)', (user_id, new_val))
        conn.commit()
        log_action(session['user_id'], 'issue_chunk', f"user={user_id}, chunk={chunk}")
    finally:
        conn.close()
    return redirect('/admin-panel')

@app.route('/api/common-add', methods=['POST'])
def api_common_add():
    if 'role' not in session:
        return redirect('/')
    cleanup_old_records()
    chunk = request.form['chunk']
    amount = float(request.form['amount'])
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('UPDATE common_fund SET amount = amount + %s WHERE chunk_name = %s', (amount, chunk))
            conn.commit()
            log_action(session['user_id'], 'common_add', f"{chunk}+{amount}")
    finally:
        conn.close()
    return redirect('/admin-panel')

@app.route('/api/common-remove', methods=['POST'])
def api_common_remove():
    if 'role' not in session:
        return redirect('/')
    cleanup_old_records()
    chunk = request.form['chunk']
    amount = float(request.form['amount'])
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('UPDATE common_fund SET amount = amount - %s WHERE chunk_name = %s', (amount, chunk))
            conn.commit()
            log_action(session['user_id'], 'common_remove', f"{chunk}-{amount}")
    finally:
        conn.close()
    return redirect('/admin-panel')

@app.route('/api/remove-admin', methods=['POST'])
def api_remove_admin():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('UPDATE users SET role = %s WHERE id = %s', ('user', user_id))
            conn.commit()
            log_action(session['user_id'], 'remove_admin', f"user={user_id}")
    finally:
        conn.close()
    return redirect('/tech-mode')

@app.route('/api/promote-to-admin', methods=['POST'])
def api_promote_to_admin():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('UPDATE users SET role = %s WHERE id = %s AND role = %s', ('admin', user_id, 'user'))
            conn.commit()
            log_action(session['user_id'], 'promote_to_admin', f"user_id={user_id}")
    finally:
        conn.close()
    return redirect('/tech-mode')

@app.route('/api/create-user', methods=['POST'])
def api_create_user():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    username = request.form['username']
    login = request.form['login']
    password = request.form['password']
    conn = get_db_connection()
    try:
        pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8')
        with conn.cursor() as c:
            c.execute('INSERT INTO users (username, login, password_hash, role) VALUES (%s, %s, %s, %s)',
                      (username, login, pwd_hash, 'user'))
            conn.commit()
            log_action(session['user_id'], 'create_user', f"login={login}, username={username}")
    except psycopg2.IntegrityError:
        pass
    finally:
        conn.close()
    return redirect('/tech-mode')

@app.route('/api/delete-user', methods=['POST'])
def api_delete_user():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('DELETE FROM users WHERE id = %s', (user_id,))
            c.execute('DELETE FROM stats WHERE user_id = %s', (user_id,))
            c.execute('DELETE FROM transfers WHERE from_user_id = %s OR to_user_id = %s', (user_id, user_id))
            conn.commit()
            log_action(session['user_id'], 'delete_user', f"user_id={user_id}")
    finally:
        conn.close()
    return redirect('/tech-mode')

@app.route('/api/change-login', methods=['POST'])
def api_change_login():
    if 'user_id' not in session:
        return redirect('/')
    cleanup_old_records()
    new_login = request.form['new_login']
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('UPDATE users SET login = %s WHERE id = %s', (new_login, session['user_id']))
            conn.commit()
    except psycopg2.IntegrityError:
        pass
    finally:
        conn.close()
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
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('UPDATE users SET password_hash = %s WHERE id = %s', (pwd_hash, session['user_id']))
            conn.commit()
            session.clear()
            return redirect('/')
    except Exception as e:
        print(f"Ошибка при смене пароля: {e}")
        return redirect('/dashboard')
    finally:
        conn.close()

@app.route('/api/request-change', methods=['POST'])
def api_request_change():
    if 'user_id' not in session:
        return redirect('/')
    cleanup_old_records()
    new_login = request.form.get('new_login')
    new_password = request.form.get('new_password')
    
    conn = get_db_connection()
    try:
        if new_password:
            pwd_hash = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode('utf-8')
            with conn.cursor() as c:
                c.execute('INSERT INTO change_requests (user_id, new_login, new_password_hash) VALUES (%s, %s, %s)',
                          (session['user_id'], new_login, pwd_hash))
        else:
            with conn.cursor() as c:
                c.execute('INSERT INTO change_requests (user_id, new_login) VALUES (%s, %s)',
                          (session['user_id'], new_login))
        conn.commit()
        details = f"login={new_login}" + (", password=***" if new_password else "")
        log_action(session['user_id'], 'request_change', details)
    finally:
        conn.close()
    return redirect('/dashboard')

@app.route('/api/approve-change', methods=['POST'])
def api_approve_change():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    request_id = request.form['request_id']
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('SELECT * FROM change_requests WHERE id = %s', (request_id,))
            req = c.fetchone()
        if req:
            updates = []
            params = []
            if req['new_login']:
                updates.append("login = %s")
                params.append(req['new_login'])
            if req['new_password_hash']:
                updates.append("password_hash = %s")
                params.append(req['new_password_hash'])
            if updates:
                params.append(req['user_id'])
                query = f"UPDATE users SET {', '.join(updates)} WHERE id = %s"
                with conn.cursor() as c:
                    c.execute(query, params)
            with conn.cursor() as c:
                c.execute('UPDATE change_requests SET status = %s WHERE id = %s', ('approved', request_id))
                log_action(session['user_id'], 'approve_change', f"request_id={request_id}, user_id={req['user_id']}")
                conn.commit()
    finally:
        conn.close()
    return redirect('/tech-mode')

@app.route('/api/reject-change', methods=['POST'])
def api_reject_change():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    request_id = request.form['request_id']
    reason = request.form['reason']
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('UPDATE change_requests SET status = %s, reason = %s WHERE id = %s', ('rejected', reason, request_id))
            log_action(session['user_id'], 'reject_change', f"request_id={request_id}, reason={reason}")
            conn.commit()
    finally:
        conn.close()
    return redirect('/tech-mode')

@app.route('/api/post-news', methods=['POST'])
def api_post_news():
    if 'role' not in session or session['role'] not in ('admin', 'admin2'):
        return redirect('/')
    cleanup_old_records()
    message = request.form['message']
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('INSERT INTO news (author_id, message, role) VALUES (%s, %s, %s)',
                      (session['user_id'], message, session['role']))
            log_action(session['user_id'], 'post_news', f"message='{message[:50]}...'")
            conn.commit()
    finally:
        conn.close()
    return redirect('/admin-panel' if session['role'] == 'admin' else '/tech-mode')

@app.route('/api/admin-change-login', methods=['POST'])
def api_admin_change_login():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    new_login = request.form['new_login']
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('UPDATE users SET login = %s WHERE id = %s', (new_login, user_id))
            conn.commit()
            log_action(session['user_id'], 'admin_change_login', f"user_id={user_id}, new_login={new_login}")
    except psycopg2.IntegrityError:
        pass
    finally:
        conn.close()
    return redirect('/tech-mode')

@app.route('/api/admin-change-password', methods=['POST'])
def api_admin_change_password():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    new_pass = request.form['new_password']
    pwd_hash = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt()).decode('utf-8')
    conn = get_db_connection()
    try:
        with conn.cursor() as c:
            c.execute('UPDATE users SET password_hash = %s WHERE id = %s', (pwd_hash, user_id))
            conn.commit()
            log_action(session['user_id'], 'admin_change_password', f"user_id={user_id}")
    except:
        pass
    finally:
        conn.close()
    return redirect('/tech-mode')

@app.route('/api/clear-reject-notice')
def api_clear_reject_notice():
    session.pop('reject_reason', None)
    return redirect('/dashboard')

@app.route('/keep-alive')
def keep_alive():
    return 'OK', 200

@app.route('/init-db')
def init_db():
    conn = get_db_connection()
    with conn.cursor() as c:
        # Таблица пользователей
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username TEXT NOT NULL,
                login TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT CHECK(role IN ('user', 'admin', 'admin2')) DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Статистика
        c.execute('''
            CREATE TABLE IF NOT EXISTS stats (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                chunk1 REAL DEFAULT 0,
                chunk2 REAL DEFAULT 0,
                chunk3 REAL DEFAULT 0,
                chunk4 REAL DEFAULT 0,
                chunk5 REAL DEFAULT 0,
                chunk6 REAL DEFAULT 0,
                chunk7 REAL DEFAULT 0,
                chunk8 REAL DEFAULT 0,
                vr1 REAL DEFAULT 0,
                vr2 REAL DEFAULT 0,
                vr3 REAL DEFAULT 0,
                core REAL DEFAULT 0
            )
        ''')

        # Передачи
        c.execute('''
            CREATE TABLE IF NOT EXISTS transfers (
                id SERIAL PRIMARY KEY,
                from_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                to_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                chunk_name TEXT NOT NULL,
                amount REAL NOT NULL,
                transferred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Общак
        c.execute('''
            CREATE TABLE IF NOT EXISTS common_fund (
                id SERIAL PRIMARY KEY,
                chunk_name TEXT NOT NULL UNIQUE,
                amount REAL DEFAULT 0
            )
        ''')

        # Аудит
        c.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id SERIAL PRIMARY KEY,
                admin_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                action TEXT NOT NULL,
                details TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Заявки
        c.execute('''
            CREATE TABLE IF NOT EXISTS change_requests (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                new_login TEXT,
                new_password_hash TEXT,
                status TEXT CHECK(status IN ('pending', 'approved', 'rejected')) DEFAULT 'pending',
                reason TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Новости
        c.execute('''
            CREATE TABLE IF NOT EXISTS news (
                id SERIAL PRIMARY KEY,
                author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                message TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Инициализация общака
        chunks = ['chunk1','chunk2','chunk3','chunk4','chunk5','chunk6','chunk7','chunk8','vr1','vr2','vr3','core']
        for ch in chunks:
            c.execute("INSERT INTO common_fund (chunk_name, amount) VALUES (%s, 0) ON CONFLICT (chunk_name) DO NOTHING", (ch,))

        # Первый пользователь
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()['count'] == 0:
            pwd_hash = bcrypt.hashpw("admin2".encode(), bcrypt.gensalt()).decode('utf-8')
            c.execute('''
                INSERT INTO users (username, login, password_hash, role)
                VALUES (%s, %s, %s, %s)
            ''', ("SupremeAdmin", "admin2", pwd_hash, "admin2"))

        conn.commit()
    conn.close()
    return "✅ База данных инициализирована! Логин: admin2 / Пароль: admin2"

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

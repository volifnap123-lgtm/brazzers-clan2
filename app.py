from flask import Flask, render_template, request, redirect, session
import sqlite3
import bcrypt
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'brazzers_secret_2026_strong'

DATABASE = 'brazzers.db'


def get_db_connection():
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def cleanup_old_records():
    """Удаляет записи старше 12 месяцев"""
    conn = get_db_connection()
    conn.execute("DELETE FROM stats WHERE updated_at < datetime('now', '-12 months')")
    conn.execute("DELETE FROM audit_log WHERE timestamp < datetime('now', '-12 months')")
    conn.commit()
    conn.close()


def log_action(admin_id, action, details):
    conn = get_db_connection()
    conn.execute('INSERT INTO audit_log (admin_id, action, details) VALUES (?, ?, ?)', (admin_id, action, str(details)))
    conn.commit()
    conn.close()


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        login_input = request.form['login']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE login = ?', (login_input,)).fetchone()
        conn.close()
        if user and bcrypt.checkpw(password.encode(), user['password_hash']):
            session.permanent = True
            app.permanent_session_lifetime = 600
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['username'] = user['username']
            return redirect('/dashboard')
        else:
            return render_template('login.html', error="Неверный логин или пароль")
    return render_template('login.html')


@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect('/')
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()

    stats_rows = conn.execute('''
        SELECT * FROM stats WHERE user_id = ? ORDER BY updated_at DESC LIMIT 10
    ''', (session['user_id'],)).fetchall()
    total = {k: sum(row[k] or 0 for row in stats_rows) for k in
             ['chunk1', 'chunk2', 'chunk3', 'chunk4', 'chunk5', 'chunk6', 'chunk7', 'chunk8', 'vr1', 'vr2', 'vr3',
              'core']}

    given = conn.execute('SELECT SUM(amount) FROM transfers WHERE from_user_id = ?', (session['user_id'],)).fetchone()[
                0] or 0

    all_users = conn.execute('''
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
    ''').fetchall()

    top5_data = conn.execute('''
        SELECT u.username,
               COALESCE(SUM(s.chunk1 + s.chunk2 + s.chunk3 + s.chunk4 + s.chunk5 + 
                            s.chunk6 + s.chunk7 + s.chunk8 + s.vr1 + s.vr2 + s.vr3 + s.core), 0) as total
        FROM users u
        LEFT JOIN stats s ON u.id = s.user_id
        GROUP BY u.id, u.username
        ORDER BY total DESC
        LIMIT 5
    ''').fetchall()
    top5 = [{'username': row['username'], 'total': round(row['total'], 1)} for row in top5_data]

    conn.close()
    return render_template('user_dashboard.html', user=user, stats_rows=stats_rows, total=total, given_percent=given,
                           all_users=all_users, top5=top5)


@app.route('/admin-panel')
def admin_panel():
    if 'role' not in session or session['role'] not in ('admin', 'admin2'):
        return redirect('/')
    conn = get_db_connection()
    users = conn.execute("SELECT id, username, login FROM users").fetchall()
    chunks = ['chunk1', 'chunk2', 'chunk3', 'chunk4', 'chunk5', 'chunk6', 'chunk7', 'chunk8', 'vr1', 'vr2', 'vr3',
              'core']
    common_fund = {row['chunk_name']: row['amount'] for row in conn.execute("SELECT * FROM common_fund").fetchall()}
    conn.close()
    return render_template('admin_panel.html', users=users, chunks=chunks, common_fund=common_fund)


@app.route('/tech-mode')
def tech_mode():
    if session.get('role') != 'admin2':
        return redirect('/admin-panel')
    conn = get_db_connection()
    logs = conn.execute("SELECT * FROM audit_log ORDER BY timestamp DESC LIMIT 50").fetchall()
    users = conn.execute("SELECT id, username, login, role FROM users").fetchall()
    conn.close()

    # Размер базы данных в МБ
    db_size = round(os.path.getsize(DATABASE) / (1024 * 1024), 2) if os.path.exists(DATABASE) else 0

    return render_template('tech_mode.html', logs=logs, users=users, db_size=db_size)


@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')


# === API ===

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
    cols = ', '.join(chunks)
    placeholders = ', '.join(['?'] * len(chunks))
    query = f'INSERT INTO stats (user_id, {cols}) VALUES (?, {placeholders})'
    conn.execute(query, [user_id] + [values[c] for c in chunks])
    conn.commit()
    log_action(session['user_id'], 'give_percent_single', f"user={user_id}, {values}")
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
    for uid in user_ids:
        last = conn.execute(f'SELECT {chunk} FROM stats WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1',
                            (uid,)).fetchone()
        current = last[chunk] if last else 0
        new_val = current + amount_per
        conn.execute(f'INSERT INTO stats (user_id, {chunk}) VALUES (?, ?)', (uid, new_val))
    conn.commit()
    log_action(session['user_id'], 'give_percent_multi', f"chunk={chunk}, users={user_ids}, each={amount_per}")
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
    last_from = conn.execute(f'SELECT {chunk} FROM stats WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1',
                             (from_id,)).fetchone()
    if not last_from or last_from[chunk] < amount:
        conn.close()
        return redirect('/admin-panel')
    new_from = last_from[chunk] - amount
    conn.execute(f'INSERT INTO stats (user_id, {chunk}) VALUES (?, ?)', (from_id, new_from))
    last_to = conn.execute(f'SELECT {chunk} FROM stats WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1',
                           (to_id,)).fetchone()
    new_to = (last_to[chunk] if last_to else 0) + amount
    conn.execute(f'INSERT INTO stats (user_id, {chunk}) VALUES (?, ?)', (to_id, new_to))
    conn.execute('INSERT INTO transfers (from_user_id, to_user_id, chunk_name, amount) VALUES (?, ?, ?, ?)',
                 (from_id, to_id, chunk, amount))
    conn.commit()
    log_action(session['user_id'], 'transfer', f"{from_id}->{to_id}, {chunk}={amount}")
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
    last = conn.execute(f'SELECT {chunk} FROM stats WHERE user_id = ? ORDER BY updated_at DESC LIMIT 1',
                        (user_id,)).fetchone()
    current = last[chunk] if last else 0
    new_val = current - 100.0
    if new_val < 0: new_val = 0
    conn.execute(f'INSERT INTO stats (user_id, {chunk}) VALUES (?, ?)', (user_id, new_val))
    conn.commit()
    log_action(session['user_id'], 'issue_chunk', f"user={user_id}, chunk={chunk}")
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
    conn.execute('UPDATE common_fund SET amount = amount + ? WHERE chunk_name = ?', (amount, chunk))
    conn.commit()
    log_action(session['user_id'], 'common_add', f"{chunk}+{amount}")
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
    conn.execute('UPDATE common_fund SET amount = amount - ? WHERE chunk_name = ?', (amount, chunk))
    conn.commit()
    log_action(session['user_id'], 'common_remove', f"{chunk}-{amount}")
    conn.close()
    return redirect('/admin-panel')


@app.route('/api/remove-admin', methods=['POST'])
def api_remove_admin():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    conn = get_db_connection()
    conn.execute('UPDATE users SET role = "user" WHERE id = ?', (user_id,))
    conn.commit()
    log_action(session['user_id'], 'remove_admin', f"user={user_id}")
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
        conn.execute('UPDATE users SET login = ? WHERE id = ?', (new_login, session['user_id']))
        conn.commit()
    except:
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
    pwd_hash = bcrypt.hashpw(new_pass.encode(), bcrypt.gensalt())
    conn = get_db_connection()
    conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (pwd_hash, session['user_id']))
    conn.commit()
    conn.close()
    return redirect('/dashboard')


@app.route('/api/promote-to-admin', methods=['POST'])
def api_promote_to_admin():
    if session.get('role') != 'admin2':
        return redirect('/tech-mode')
    cleanup_old_records()
    user_id = request.form['user_id']
    conn = get_db_connection()
    conn.execute('UPDATE users SET role = "admin" WHERE id = ? AND role = "user"', (user_id,))
    conn.commit()
    log_action(session['user_id'], 'promote_to_admin', f"user_id={user_id}")
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
        pwd_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        conn.execute('INSERT INTO users (username, login, password_hash, role) VALUES (?, ?, ?, ?)',
                     (username, login, pwd_hash, 'user'))
        conn.commit()
        log_action(session['user_id'], 'create_user', f"login={login}, username={username}")
    except sqlite3.IntegrityError:
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
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.execute('DELETE FROM stats WHERE user_id = ?', (user_id,))
    conn.execute('DELETE FROM transfers WHERE from_user_id = ? OR to_user_id = ?', (user_id, user_id))
    conn.commit()
    log_action(session['user_id'], 'delete_user', f"user_id={user_id}")
    conn.close()
    return redirect('/tech-mode')

@app.route('/keep-alive')
def keep_alive():
    return 'OK', 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

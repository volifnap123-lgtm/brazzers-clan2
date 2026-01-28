import sqlite3
import bcrypt

def init_db():
    conn = sqlite3.connect('brazzers.db', check_same_thread=False)
    c = conn.cursor()

    # Пользователи
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
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
            core REAL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Передачи
    c.execute('''
        CREATE TABLE IF NOT EXISTS transfers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            from_user_id INTEGER NOT NULL,
            to_user_id INTEGER NOT NULL,
            chunk_name TEXT NOT NULL,
            amount REAL NOT NULL,
            transferred_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(from_user_id) REFERENCES users(id),
            FOREIGN KEY(to_user_id) REFERENCES users(id)
        )
    ''')

    # Общак
    c.execute('''
        CREATE TABLE IF NOT EXISTS common_fund (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chunk_name TEXT NOT NULL UNIQUE,
            amount REAL DEFAULT 0
        )
    ''')

    # Аудит
    c.execute('''
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            admin_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            details TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(admin_id) REFERENCES users(id)
        )
    ''')

    # Заявки на смену
    c.execute('''
        CREATE TABLE IF NOT EXISTS change_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            new_login TEXT,
            new_password_hash TEXT,
            status TEXT CHECK(status IN ('pending', 'approved', 'rejected')) DEFAULT 'pending',
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    # Новости
    c.execute('''
        CREATE TABLE IF NOT EXISTS news (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            author_id INTEGER NOT NULL,
            message TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(author_id) REFERENCES users(id)
        )
    ''')

    # Инициализация общака
    chunks = ['chunk1','chunk2','chunk3','chunk4','chunk5','chunk6','chunk7','chunk8','vr1','vr2','vr3','core']
    for ch in chunks:
        c.execute("INSERT OR IGNORE INTO common_fund (chunk_name, amount) VALUES (?, 0)", (ch,))

    # Первый пользователь
    c.execute("SELECT COUNT(*) FROM users")
    if c.fetchone()[0] == 0:
        pwd_hash = bcrypt.hashpw("admin2".encode(), bcrypt.gensalt())
        c.execute('''
            INSERT INTO users (username, login, password_hash, role)
            VALUES (?, ?, ?, ?)
        ''', ("SupremeAdmin", "admin2", pwd_hash, "admin2"))

    conn.commit()
    conn.close()
    print("✅ База данных инициализирована. Логин: admin2 / Пароль: admin2")

if __name__ == "__main__":
    init_db()
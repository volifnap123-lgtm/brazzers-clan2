const CONFIG = {
    SUPABASE_URL: 'https://qjgzhtkpwamounnpgepr.supabase.co',
    SUPABASE_KEY: 'sb_publishable_WV7YnhP_OAWYx8gQjOmG1Q_7GdKOVlV',
    CHUNKS: ['chunk1', 'chunk2', 'chunk3', 'chunk4', 'chunk5', 'chunk6', 'chunk7', 'chunk8', 'vr1', 'vr2', 'vr3', 'core']
};

const CHUNK_LABELS = {
    chunk1: 'Кусок №1',
    chunk2: 'Кусок №2', 
    chunk3: 'Кусок №3',
    chunk4: 'Кусок №4',
    chunk5: 'Кусок №5',
    chunk6: 'Кусок №6',
    chunk7: 'Кусок №7',
    chunk8: 'Кусок №8',
    vr1: 'В.Рад №1',
    vr2: 'В.Рад №2',
    vr3: 'В.Рад №3',
    core: 'Ядро'
};

const ROLE_LABELS = {
    user: 'Пользователь',
    admin: 'Администратор',
    admin2: 'Главный админ'
};

function saveSession(user) {
    localStorage.setItem('session', JSON.stringify(user));
}

function getSession() {
    const s = localStorage.getItem('session');
    return s ? JSON.parse(s) : null;
}

function clearSession() {
    localStorage.removeItem('session');
}
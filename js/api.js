const { createClient } = supabase;
const supabaseClient = createClient(CONFIG.SUPABASE_URL, CONFIG.SUPABASE_KEY);

async function apiLogin(login, password) {
    const { data, error } = await supabaseClient
        .from('users')
        .select('*')
        .eq('login', login)
        .single();
    
    if (error || !data) throw new Error('Пользователь не найден');
    
    const passwordMatch = await bcrypt.checkpw(password.encode(), data.password_hash.encode());
    if (!passwordMatch) throw new Error('Неверный пароль');
    
    saveSession(data);
    return data;
}

async function apiGetUser(userId) {
    const { data, error } = await supabaseClient
        .from('users')
        .select('*')
        .eq('id', userId)
        .single();
    if (error) throw error;
    return data;
}

async function apiGetAllUsers() {
    const { data, error } = await supabaseClient
        .from('users')
        .select('id, username, login, role');
    if (error) throw error;
    return data || [];
}

async function apiGetUserStats(userId) {
    const { data, error } = await supabaseClient
        .from('stats')
        .select('*')
        .eq('user_id', userId)
        .order('updated_at', { ascending: false })
        .limit(10);
    if (error) throw error;
    return data || [];
}

async function apiGetUserTotalStats(userId) {
    const { data, error } = await supabaseClient
        .from('stats')
        .select('*')
        .eq('user_id', userId);
    if (error) throw error;
    
    const total = {};
    for (const chunk of CONFIG.CHUNKS) {
        total[chunk] = data.reduce((sum, row) => sum + (row[chunk] || 0), 0);
    }
    return total;
}

async function apiGetIssuedChunks(userId) {
    const { data, error } = await supabaseClient
        .from('issued_chunks')
        .select('chunk_name')
        .eq('user_id', userId);
    if (error) throw error;
    
    const counts = {};
    for (const chunk of CONFIG.CHUNKS) {
        counts[chunk] = data.filter(d => d.chunk_name === chunk).length;
    }
    const sixB13 = Object.values(counts).reduce((min, c) => Math.min(min, c), Infinity);
    return { counts, six_b13: isFinite(sixB13) ? sixB13 : 0 };
}

async function apiGetTransfers(userId) {
    const { data, error } = await supabaseClient
        .from('transfers')
        .select('amount')
        .eq('from_user_id', userId);
    if (error) throw error;
    return data.reduce((sum, row) => sum + (row.amount || 0), 0);
}

async function apiGetCommonFund() {
    const { data, error } = await supabaseClient
        .from('stats')
        .select('*');
    if (error) throw error;
    
    const fund = {};
    for (const chunk of CONFIG.CHUNKS) {
        fund[chunk] = data.reduce((sum, row) => sum + (row[chunk] || 0), 0);
    }
    return fund;
}

async function apiGetRemainder() {
    const { data, error } = await supabaseClient
        .from('remainder')
        .select('chunk_name, amount');
    if (error) throw error;
    
    const remainder = {};
    for (const chunk of CONFIG.CHUNKS) {
        const row = data.find(d => d.chunk_name === chunk);
        remainder[chunk] = row ? parseFloat(row.amount) : 0;
    }
    return remainder;
}

async function apiGetNews() {
    const { data, error } = await supabaseClient
        .from('news')
        .select('*')
        .order('created_at', { ascending: false });
    if (error) throw error;
    return data || [];
}

async function apiGetChunkRequests() {
    const { data, error } = await supabaseClient
        .from('chunk_requests')
        .select('*')
        .eq('status', 'pending');
    if (error) throw error;
    return data || [];
}

async function apiGetChangeRequests() {
    const { data, error } = await supabaseClient
        .from('change_requests')
        .select('*')
        .eq('status', 'pending')
        .order('created_at', { ascending: false });
    if (error) throw error;
    return data || [];
}

async function apiGetAuditLogs(limit = 50) {
    const { data, error } = await supabaseClient
        .from('audit_log')
        .select('*')
        .order('timestamp', { ascending: false })
        .limit(limit);
    if (error) throw error;
    return data || [];
}

async function apiGivePercentSingle(userId, chunks, adminId) {
    const values = { user_id: userId };
    for (const chunk of CONFIG.CHUNKS) {
        values[chunk] = parseFloat(chunks[chunk]) || 0;
    }
    
    await supabaseClient.from('stats').insert(values);
    await logAction(adminId, 'give_percent_single', `user=${userId}`);
}

async function apiGivePercentMultiple(userIds, chunk, adminId) {
    const amountPer = 100 / userIds.length;
    const remainderAmount = 100 - (amountPer * userIds.length);
    
    for (const userId of userIds) {
        const values = { user_id: userId };
        for (const c of CONFIG.CHUNKS) values[c] = 0;
        values[chunk] = amountPer;
        await supabaseClient.from('stats').insert(values);
    }
    
    if (Math.abs(remainderAmount) > 0.01) {
        const { data } = await supabaseClient
            .from('remainder')
            .select('amount')
            .eq('chunk_name', chunk)
            .single();
        
        if (data) {
            await supabaseClient
                .from('remainder')
                .update({ amount: data.amount + remainderAmount })
                .eq('chunk_name', chunk);
        } else {
            await supabaseClient
                .from('remainder')
                .insert({ chunk_name: chunk, amount: remainderAmount });
        }
    }
    
    await logAction(adminId, 'give_percent_multi', `chunk=${chunk}, users=${userIds.length}`);
}

async function apiTransferPercent(fromUserId, toUserId, chunk, amount, adminId) {
    const { data: fromStats } = await supabaseClient
        .from('stats')
        .select(chunk)
        .eq('user_id', fromUserId);
    
    const balance = fromStats.reduce((sum, row) => sum + (row[chunk] || 0), 0);
    if (balance < amount) throw new Error('Недостаточно средств');
    
    const fromValues = { user_id: fromUserId };
    for (const c of CONFIG.CHUNKS) fromValues[c] = 0;
    fromValues[chunk] = -amount;
    await supabaseClient.from('stats').insert(fromValues);
    
    const toValues = { user_id: toUserId };
    for (const c of CONFIG.CHUNKS) toValues[c] = 0;
    toValues[chunk] = amount;
    await supabaseClient.from('stats').insert(toValues);
    
    await supabaseClient.from('transfers').insert({
        from_user_id: fromUserId,
        to_user_id: toUserId,
        chunk_name: chunk,
        amount: amount
    });
    
    await logAction(null, 'transfer', `${fromUserId}->${toUserId}, ${chunk}=${amount}`);
}

async function apiGiveFromRemainder(userId, chunks, adminId) {
    const remainder = await apiGetRemainder();
    
    for (const chunk of CONFIG.CHUNKS) {
        const amount = parseFloat(chunks[chunk]) || 0;
        if (amount > 0) {
            const values = { user_id: userId };
            for (const c of CONFIG.CHUNKS) values[c] = 0;
            values[chunk] = amount;
            await supabaseClient.from('stats').insert(values);
            
            const newRemainder = (remainder[chunk] || 0) - amount;
            await supabaseClient
                .from('remainder')
                .update({ amount: newRemainder })
                .eq('chunk_name', chunk);
        }
    }
    
    await logAction(adminId, 'give_from_remainder', `user=${userId}`);
}

async function apiRequestChunk(userId, chunk) {
    const total = await apiGetUserTotalStats(userId);
    if ((total[chunk] || 0) < 100) throw new Error('Недостаточно процентов');
    
    const values = { user_id: userId };
    for (const c of CONFIG.CHUNKS) values[c] = 0;
    values[chunk] = -100;
    await supabaseClient.from('stats').insert(values);
    
    await supabaseClient.from('chunk_requests').insert({
        user_id: userId,
        chunk_name: chunk,
        status: 'pending'
    });
}

async function apiApproveChunkRequest(requestId, adminId) {
    const { data: req } = await supabaseClient
        .from('chunk_requests')
        .select('*')
        .eq('id', requestId)
        .single();
    
    if (!req) return;
    
    await supabaseClient.from('issued_chunks').insert({
        user_id: req.user_id,
        chunk_name: req.chunk_name
    });
    
    await supabaseClient
        .from('chunk_requests')
        .update({ status: 'approved' })
        .eq('id', requestId);
    
    await logAction(adminId, 'chunk_request_approved', `user=${req.user_id}`);
}

async function apiRejectChunkRequest(requestId, reason, adminId) {
    const { data: req } = await supabaseClient
        .from('chunk_requests')
        .select('*')
        .eq('id', requestId)
        .single();
    
    if (!req) return;
    
    const values = { user_id: req.user_id };
    for (const c of CONFIG.CHUNKS) values[c] = 0;
    values[req.chunk_name] = 100;
    await supabaseClient.from('stats').insert(values);
    
    await supabaseClient
        .from('chunk_requests')
        .update({ status: 'rejected', reason: reason })
        .eq('id', requestId);
    
    await logAction(adminId, 'chunk_request_rejected', `user=${req.user_id}, reason=${reason}`);
}

async function apiPostNews(authorId, message, role) {
    await supabaseClient.from('news').insert({
        author_id: authorId,
        message: message,
        role: role
    });
}

async function apiChangeLogin(userId, newLogin) {
    await supabaseClient
        .from('users')
        .update({ login: newLogin })
        .eq('id', userId);
}

async function apiChangePassword(userId, newPassword) {
    const pwdHash = await bcrypt.hashpw(newPassword.encode(), bcrypt.gensalt()).decode('utf-8');
    await supabaseClient
        .from('users')
        .update({ password_hash: pwdHash })
        .eq('id', userId);
}

async function apiRequestChange(userId, newLogin, newPassword) {
    const insertData = { user_id: userId, status: 'pending' };
    if (newLogin) insertData.new_login = newLogin;
    if (newPassword) {
        const pwdHash = await bcrypt.hashpw(newPassword.encode(), bcrypt.gensalt()).decode('utf-8');
        insertData.new_password_hash = pwdHash;
    }
    await supabaseClient.from('change_requests').insert(insertData);
}

async function apiApproveChange(requestId, adminId) {
    const { data: req } = await supabaseClient
        .from('change_requests')
        .select('*')
        .eq('id', requestId)
        .single();
    
    if (!req) return;
    
    const updateData = {};
    if (req.new_login) updateData.login = req.new_login;
    if (req.new_password_hash) updateData.password_hash = req.new_password_hash;
    
    if (Object.keys(updateData).length > 0) {
        await supabaseClient
            .from('users')
            .update(updateData)
            .eq('id', req.user_id);
    }
    
    await supabaseClient
        .from('change_requests')
        .update({ status: 'approved' })
        .eq('id', requestId);
    
    await logAction(adminId, 'approve_change', `request=${requestId}`);
}

async function apiRejectChange(requestId, reason, adminId) {
    await supabaseClient
        .from('change_requests')
        .update({ status: 'rejected', reason: reason })
        .eq('id', requestId);
    
    await logAction(adminId, 'reject_change', `request=${requestId}, reason=${reason}`);
}

async function apiCreateUser(username, login, password, adminId) {
    const pwdHash = await bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode('utf-8');
    await supabaseClient.from('users').insert({
        username: username,
        login: login,
        password_hash: pwdHash,
        role: 'user'
    });
    await logAction(adminId, 'create_user', `login=${login}`);
}

async function apiDeleteUser(userId, adminId) {
    await supabaseClient.from('users').delete().eq('id', userId);
    await supabaseClient.from('stats').delete().eq('user_id', userId);
    await logAction(adminId, 'delete_user', `user=${userId}`);
}

async function apiPromoteToAdmin(userId, adminId) {
    await supabaseClient
        .from('users')
        .update({ role: 'admin' })
        .eq('id', userId)
        .eq('role', 'user');
    await logAction(adminId, 'promote_to_admin', `user=${userId}`);
}

async function apiRemoveAdmin(userId, adminId) {
    await supabaseClient
        .from('users')
        .update({ role: 'user' })
        .eq('id', userId);
    await logAction(adminId, 'remove_admin', `user=${userId}`);
}

async function apiAdminChangeLogin(userId, newLogin, adminId) {
    await supabaseClient
        .from('users')
        .update({ login: newLogin })
        .eq('id', userId);
    await logAction(adminId, 'admin_change_login', `user=${userId}`);
}

async function apiAdminChangePassword(userId, newPassword, adminId) {
    const pwdHash = await bcrypt.hashpw(newPassword.encode(), bcrypt.gensalt()).decode('utf-8');
    await supabaseClient
        .from('users')
        .update({ password_hash: pwdHash })
        .eq('id', userId);
    await logAction(adminId, 'admin_change_password', `user=${userId}`);
}

async function apiCommonAdd(chunk, amount, adminId) {
    const { data } = await supabaseClient
        .from('common_fund')
        .select('amount')
        .eq('chunk_name', chunk)
        .single();
    
    const current = data ? data.amount : 0;
    await supabaseClient
        .from('common_fund')
        .upsert({ chunk_name: chunk, amount: current + amount });
    
    await logAction(adminId, 'common_add', `${chunk}+${amount}`);
}

async function apiCommonRemove(chunk, amount, adminId) {
    const { data } = await supabaseClient
        .from('common_fund')
        .select('amount')
        .eq('chunk_name', chunk)
        .single();
    
    const current = data ? data.amount : 0;
    await supabaseClient
        .from('common_fund')
        .upsert({ chunk_name: chunk, amount: current - amount });
    
    await logAction(adminId, 'common_remove', `${chunk}-${amount}`);
}

async function logAction(adminId, action, details) {
    try {
        await supabaseClient.from('audit_log').insert({
            admin_id: adminId,
            action: action,
            details: details
        });
    } catch (e) {
        console.error('Log error:', e);
    }
}
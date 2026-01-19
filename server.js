/**
 * Purple Fortune Slots - Backend Server
 * Optimized for Railway.app deployment with MongoDB Atlas
 */

require('dotenv').config();

const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');

const app = express();

// ==================== CONFIGURATION ====================
const CONFIG = {
    PORT: process.env.PORT || 8080,
    NODE_ENV: process.env.NODE_ENV || 'development',
    MONGODB_URI: process.env.MONGODB_URI 
    TELEGRAM_BOT_TOKEN: process.env.TELEGRAM_BOT_TOKEN,
    CRYPTO_BOT_API_KEY: process.env.CRYPTO_BOT_API_KEY,
    CRYPTO_BOT_API_URL: 'https://pay.crypt.bot/api',
    FRONTEND_URL: process.env.FRONTEND_URL 
    WEBHOOK_SECRET: process.env.WEBHOOK_SECRET || crypto.randomBytes(32).toString('hex'),
    WEBHOOK_URL: process.env.WEBHOOK_URL || `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/webhook/cryptobot`
    MIN_BET: 1,
    MAX_BET: 50000,
    MIN_DEPOSIT: 1,
    MAX_DEPOSIT: 10000,
    MIN_WITHDRAW: 20,
    WITHDRAW_FEE_PERCENT: 0.01,
    WITHDRAW_FEE_MIN: 1,
    DEMO_BALANCE: 1000
};

// ==================== TELEGRAM VALIDATION ====================
function validateTelegramData(initData) {
    try {
        if (CONFIG.NODE_ENV === 'development') {
            console.log('⚠️  Telegram validation skipped in development');
            return true;
        }

        if (!initData) return false;
        
        const urlParams = new URLSearchParams(initData);
        const hash = urlParams.get('hash');
        
        if (!hash) return false;
        
        urlParams.delete('hash');
        const dataCheckString = Array.from(urlParams.keys())
            .sort()
            .map(key => `${key}=${urlParams.get(key)}`)
            .join('\n');
        
        const secretKey = crypto.createHmac('sha256', 'WebAppData')
            .update(CONFIG.TELEGRAM_BOT_TOKEN || '')
            .digest();
        
        const calculatedHash = crypto
            .createHmac('sha256', secretKey)
            .update(dataCheckString)
            .digest('hex');
        
        return calculatedHash === hash;
    } catch (error) {
        console.error('Telegram validation error:', error);
        return false;
    }
}

// ==================== MIDDLEWARE ====================
app.use(cors({
    origin: CONFIG.FRONTEND_URL,
    credentials: true,
    methods: ['GET', 'POST', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-User-ID', 'X-User-Hash']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Health check for Railway
app.get('/health', (req, res) => {
    res.json({
        status: 'healthy',
        timestamp: new Date().toISOString(),
        mongodb: mongoose.connection.readyState === 1,
        cryptobot: CONFIG.CRYPTO_BOT_API_KEY ? 'configured' : 'mock'
    });
});

// Auth middleware
const authMiddleware = (req, res, next) => {
    const userId = req.headers['x-user-id'];
    const userHash = req.headers['x-user-hash'];
    
    if (!userId || !userHash || !validateTelegramData(userHash)) {
        if (CONFIG.NODE_ENV === 'production') {
            return res.status(401).json({ success: false, error: 'Unauthorized' });
        }
        console.log('⚠️  Auth bypassed in development');
    }
    
    req.userId = userId;
    next();
};

// ==================== MONGODB CONNECTION ====================
const connectWithRetry = async () => {
    try {
        await mongoose.connect(CONFIG.MONGODB_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            maxPoolSize: 10,
            serverSelectionTimeoutMS: 5000,
            socketTimeoutMS: 45000,
            bufferCommands: false
        });
        
        console.log('✅ MongoDB connected successfully');
        
        // Create indexes
        await createIndexes();
        
    } catch (error) {
        console.error('❌ MongoDB connection error:', error.message);
        setTimeout(connectWithRetry, 5000);
    }
};

mongoose.connection.on('error', (err) => {
    console.error('MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
    console.log('MongoDB disconnected. Attempting to reconnect...');
    setTimeout(connectWithRetry, 5000);
});

// ==================== DATABASE SCHEMAS ====================
const userSchema = new mongoose.Schema({
    telegramId: { type: String, required: true, unique: true, index: true },
    username: String,
    firstName: String,
    lastName: String,
    balance: { type: Number, default: CONFIG.DEMO_BALANCE, min: 0 },
    totalDeposited: { type: Number, default: 0 },
    totalWithdrawn: { type: Number, default: 0 },
    totalWins: { type: Number, default: 0 },
    gamesPlayed: { type: Number, default: 0 },
    lastActivity: { type: Date, default: Date.now },
    createdAt: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true },
    isDemo: { type: Boolean, default: false }
});

const invoiceSchema = new mongoose.Schema({
    userId: { type: String, required: true, index: true },
    amount: { type: Number, required: true },
    invoiceId: { type: String, required: true, unique: true, index: true },
    address: String,
    network: { type: String, default: 'TRC20' },
    asset: { type: String, default: 'USDT' },
    status: { type: String, enum: ['pending', 'paid', 'expired', 'cancelled'], default: 'pending' },
    paymentAmount: Number,
    paidAt: Date,
    expiresAt: { type: Date, default: () => new Date(Date.now() + 30 * 60 * 1000) },
    createdAt: { type: Date, default: Date.now }
});

const withdrawSchema = new mongoose.Schema({
    userId: { type: String, required: true, index: true },
    amount: { type: Number, required: true },
    fee: { type: Number, required: true },
    totalAmount: { type: Number, required: true },
    checkCode: { type: String, required: true, unique: true, index: true },
    checkId: String,
    status: { type: String, enum: ['pending', 'processing', 'completed', 'cancelled', 'failed'], default: 'pending' },
    createdAt: { type: Date, default: Date.now },
    completedAt: Date
});

const gameHistorySchema = new mongoose.Schema({
    userId: { type: String, required: true, index: true },
    type: { type: String, enum: ['spin', 'deposit', 'withdraw', 'win', 'bonus'], required: true },
    bet: Number,
    win: Number,
    balanceBefore: Number,
    balanceAfter: Number,
    result: [String],
    details: mongoose.Schema.Types.Mixed,
    timestamp: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);
const Invoice = mongoose.model('Invoice', invoiceSchema);
const Withdraw = mongoose.model('Withdraw', withdrawSchema);
const GameHistory = mongoose.model('GameHistory', gameHistorySchema);

// ==================== DATABASE INDEXES ====================
async function createIndexes() {
    try {
        // Users indexes
        await User.collection.createIndex({ telegramId: 1 }, { unique: true });
        await User.collection.createIndex({ lastActivity: -1 });
        
        // Invoices indexes
        await Invoice.collection.createIndex({ invoiceId: 1 }, { unique: true });
        await Invoice.collection.createIndex({ userId: 1, status: 1 });
        await Invoice.collection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 86400 });
        
        // Withdraws indexes
        await Withdraw.collection.createIndex({ checkCode: 1 }, { unique: true });
        await Withdraw.collection.createIndex({ userId: 1, status: 1 });
        await Withdraw.collection.createIndex({ createdAt: -1 });
        
        // Game history indexes
        await GameHistory.collection.createIndex({ userId: 1, timestamp: -1 });
        await GameHistory.collection.createIndex({ type: 1 });
        
        console.log('✅ Database indexes created');
    } catch (error) {
        console.error('Error creating indexes:', error);
    }
}

// ==================== CRYPTO BOT API ====================
class CryptoBotAPI {
    constructor(apiKey, isMock = false) {
        this.apiKey = apiKey;
        this.isMock = isMock || !apiKey;
        this.headers = {
            'Crypto-Pay-API-Token': apiKey,
            'Content-Type': 'application/json'
        };
    }
    
    async createInvoice(amount, asset = 'USDT', description = 'Purple Fortune Deposit') {
        if (this.isMock) {
            return {
                success: true,
                invoiceId: 'INV_' + crypto.randomBytes(8).toString('hex').toUpperCase(),
                address: 'T' + crypto.randomBytes(20).toString('hex').toUpperCase(),
                network: 'TRC20',
                amount: amount.toString()
            };
        }
        
        try {
            const response = await axios.post(`${CONFIG.CRYPTO_BOT_API_URL}/createInvoice`, {
                asset,
                amount: amount.toString(),
                description,
                hidden_message: `Deposit $${amount}`,
                paid_btn_name: 'callback',
                paid_btn_url: `https://t.me/${CONFIG.BOT_USERNAME}`,
                payload: JSON.stringify({ type: 'deposit', timestamp: Date.now() })
            }, { headers: this.headers });
            
            return {
                success: true,
                invoiceId: response.data.result.invoice_id,
                address: response.data.result.address,
                network: response.data.result.network,
                amount: response.data.result.amount
            };
        } catch (error) {
            console.error('CryptoBot createInvoice error:', error.response?.data || error.message);
            return { success: false, error: error.response?.data?.error || error.message };
        }
    }
    
    async getInvoice(invoiceId) {
        if (this.isMock) {
            // 70% шанс оплаты через 2 минуты (для тестов)
            const isPaid = Math.random() > 0.3 && Date.now() % 1000 < 700;
            return {
                success: true,
                status: isPaid ? 'paid' : 'active',
                paidAmount: isPaid ? '100' : null,
                paidAt: isPaid ? new Date() : null
            };
        }
        
        try {
            const response = await axios.get(`${CONFIG.CRYPTO_BOT_API_URL}/getInvoices`, {
                headers: this.headers,
                params: { invoice_ids: invoiceId }
            });
            
            if (response.data.result?.items?.length > 0) {
                const invoice = response.data.result.items[0];
                return {
                    success: true,
                    status: invoice.status,
                    paidAmount: invoice.paid_amount,
                    paidAt: invoice.paid_at ? new Date(invoice.paid_at * 1000) : null
                };
            }
            return { success: false, error: 'Invoice not found' };
        } catch (error) {
            console.error('CryptoBot getInvoice error:', error.response?.data || error.message);
            return { success: false, error: error.response?.data?.error || error.message };
        }
    }
    
    async createCheck(asset, amount) {
        if (this.isMock) {
            const checkCode = 'CHK_' + crypto.randomBytes(6).toString('hex').toUpperCase();
            return {
                success: true,
                checkCode,
                checkId: 'CHECK_' + crypto.randomBytes(4).toString('hex'),
                botCheckUrl: `https://t.me/CryptoBot?start=${checkCode}`,
                url: `https://t.me/CryptoBot?start=${checkCode}`
            };
        }
        
        try {
            const response = await axios.post(`${CONFIG.CRYPTO_BOT_API_URL}/createCheck`, {
                asset,
                amount: amount.toString(),
                name: 'Purple Fortune Withdraw'
            }, { headers: this.headers });
            
            return {
                success: true,
                checkCode: response.data.result.hash,
                checkId: response.data.result.check_id,
                botCheckUrl: response.data.result.bot_check_url,
                url: response.data.result.url
            };
        } catch (error) {
            console.error('CryptoBot createCheck error:', error.response?.data || error.message);
            return { success: false, error: error.response?.data?.error || error.message };
        }
    }
    
    async getCheck(checkId) {
        if (this.isMock) {
            return { success: true, status: 'active' };
        }
        
        try {
            const response = await axios.get(`${CONFIG.CRYPTO_BOT_API_URL}/getChecks`, {
                headers: this.headers,
                params: { check_ids: checkId }
            });
            
            if (response.data.result?.items?.length > 0) {
                const check = response.data.result.items[0];
                return {
                    success: true,
                    status: check.status,
                    activatedAt: check.activated_at ? new Date(check.activated_at * 1000) : null
                };
            }
            return { success: false, error: 'Check not found' };
        } catch (error) {
            console.error('CryptoBot getCheck error:', error.response?.data || error.message);
            return { success: false, error: error.response?.data?.error || error.message };
        }
    }
}

const cryptoBotAPI = new CryptoBotAPI(CONFIG.CRYPTO_BOT_API_KEY);

// ==================== SERVICE FUNCTIONS ====================
async function getOrCreateUser(telegramId, userData = {}) {
    try {
        let user = await User.findOne({ telegramId });
        
        if (!user) {
            user = new User({
                telegramId,
                username: userData.username || null,
                firstName: userData.first_name || null,
                lastName: userData.last_name || null,
                balance: CONFIG.DEMO_BALANCE,
                isDemo: CONFIG.NODE_ENV === 'development'
            });
            await user.save();
            console.log(`New user created: ${telegramId}`);
        } else {
            user.lastActivity = new Date();
            await user.save();
        }
        
        return user;
    } catch (error) {
        console.error('Error in getOrCreateUser:', error);
        throw error;
    }
}

function generateCheckCode() {
    return 'CHK_' + crypto.randomBytes(6).toString('hex').toUpperCase();
}

// ==================== API ROUTES ====================
app.get('/api/balance', authMiddleware, async (req, res) => {
    try {
        const user = await getOrCreateUser(req.userId, req.body.userData || {});
        res.json({ 
            success: true, 
            balance: user.balance,
            totalDeposited: user.totalDeposited,
            totalWithdrawn: user.totalWithdrawn,
            totalWins: user.totalWins,
            gamesPlayed: user.gamesPlayed
        });
    } catch (error) {
        console.error('Balance error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.post('/api/spin', authMiddleware, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
        const { bet, timestamp } = req.body;
        const userId = req.userId;
        
        // Validation
        if (!bet || bet < CONFIG.MIN_BET || bet > CONFIG.MAX_BET) {
            throw new Error(`Ставка должна быть от ${CONFIG.MIN_BET} до ${CONFIG.MAX_BET}`);
        }
        
        // Fetch user and lock document
        const user = await User.findOne({ telegramId: userId }).session(session);
        
        if (!user) {
            throw new Error('User not found');
        }
        
        if (user.balance < bet) {
            throw new Error('Недостаточно средств');
        }
        
        // Game logic
        const results = [];
        for (let i = 0; i < 3; i++) {
            results.push(getWeightedSymbol().emoji);
        }
        
        let winAmount = 0;
        const balanceBefore = user.balance;
        
        // Check combinations
        if (results[0] === results[1] && results[1] === results[2]) {
            const symbol = symbols.find(s => s.emoji === results[0]);
            winAmount = bet * symbol.multiplier;
        } else if (results[0] === results[1] || results[1] === results[2] || results[0] === results[2]) {
            winAmount = bet * 2;
        }
        
        // Update user
        user.balance = balanceBefore - bet + winAmount;
        user.gamesPlayed += 1;
        if (winAmount > 0) {
            user.totalWins += winAmount;
        }
        
        await user.save({ session });
        
        // Save game history
        const gameHistory = new GameHistory({
            userId,
            type: 'spin',
            bet,
            win: winAmount,
            balanceBefore,
            balanceAfter: user.balance,
            result: results
        });
        await gameHistory.save({ session });
        
        await session.commitTransaction();
        session.endSession();
        
        res.json({
            success: true,
            results,
            win: winAmount,
            newBalance: user.balance,
            balanceBefore
        });
        
    } catch (error) {
        await session.abortTransaction();
        session.endSession();
        
        console.error('Spin transaction error:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

app.post('/api/create-invoice', authMiddleware, async (req, res) => {
    try {
        const { amount, asset = 'USDT' } = req.body;
        const userId = req.userId;
        
        // Validation
        if (!amount || amount < CONFIG.MIN_DEPOSIT || amount > CONFIG.MAX_DEPOSIT) {
            return res.status(400).json({ 
                success: false, 
                error: `Минимум ${CONFIG.MIN_DEPOSIT}, максимум ${CONFIG.MAX_DEPOSIT} USDT` 
            });
        }
        
        // Rate limiting: max 3 pending invoices per user
        const pendingCount = await Invoice.countDocuments({ 
            userId, 
            status: 'pending',
            createdAt: { $gt: new Date(Date.now() - 30 * 60 * 1000) }
        });
        
        if (pendingCount >= 3) {
            return res.status(400).json({ 
                success: false, 
                error: 'У вас уже есть 3 неоплаченных счета. Подождите оплаты или отмены.' 
            });
        }
        
        // Create invoice in CryptoBot
        const invoiceResult = await cryptoBotAPI.createInvoice(amount, asset);
        
        if (!invoiceResult.success) {
            return res.status(500).json({ success: false, error: invoiceResult.error });
        }
        
        // Save to database
        const invoice = new Invoice({
            userId,
            amount,
            invoiceId: invoiceResult.invoiceId,
            address: invoiceResult.address,
            network: invoiceResult.network,
            asset
        });
        
        await invoice.save();
        
        res.json({
            success: true,
            invoice: {
                address: invoiceResult.address,
                network: invoiceResult.network,
                amount: invoiceResult.amount,
                invoiceId: invoiceResult.invoiceId
            },
            invoiceId: invoiceResult.invoiceId
        });
        
    } catch (error) {
        console.error('Create invoice error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.get('/api/check-invoice', authMiddleware, async (req, res) => {
    try {
        const { invoiceId } = req.query;
        const userId = req.userId;
        
        // Find invoice
        const invoice = await Invoice.findOne({ invoiceId, userId });
        
        if (!invoice) {
            return res.status(404).json({ success: false, error: 'Invoice not found' });
        }
        
        // If already paid, return immediately
        if (invoice.status === 'paid') {
            return res.json({ success: true, status: 'paid', amount: invoice.amount });
        }
        
        // Check with CryptoBot
        const invoiceStatus = await cryptoBotAPI.getInvoice(invoiceId);
        
        if (!invoiceStatus.success) {
            return res.status(500).json({ success: false, error: invoiceStatus.error });
        }
        
        // Update if paid
        if (invoiceStatus.status === 'paid' && invoice.status !== 'paid') {
            const session = await mongoose.startSession();
            session.startTransaction();
            
            try {
                // Update invoice
                invoice.status = 'paid';
                invoice.paymentAmount = parseFloat(invoiceStatus.paidAmount);
                invoice.paidAt = invoiceStatus.paidAt || new Date();
                await invoice.save({ session });
                
                // Update user balance
                const user = await User.findOne({ telegramId: userId }).session(session);
                if (user) {
                    user.balance += invoice.amount;
                    user.totalDeposited += invoice.amount;
                    await user.save({ session });
                    
                    // Save history
                    const history = new GameHistory({
                        userId,
                        type: 'deposit',
                        win: invoice.amount,
                        balanceBefore: user.balance - invoice.amount,
                        balanceAfter: user.balance,
                        details: {
                            invoiceId,
                            amount: invoice.amount,
                            network: invoice.network
                        }
                    });
                    await history.save({ session });
                }
                
                await session.commitTransaction();
                session.endSession();
                
                res.json({ success: true, status: 'paid', amount: invoice.amount, newBalance: user.balance });
                
            } catch (error) {
                await session.abortTransaction();
                session.endSession();
                throw error;
            }
        } else {
            res.json({ success: true, status: invoiceStatus.status, amount: invoice.amount });
        }
        
    } catch (error) {
        console.error('Check invoice error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

app.post('/api/create-withdraw', authMiddleware, async (req, res) => {
    const session = await mongoose.startSession();
    session.startTransaction();
    
    try {
        const { amount } = req.body;
        const userId = req.userId;
        
        // Validation
        if (!amount || amount < CONFIG.MIN_WITHDRAW) {
            throw new Error(`Минимальная сумма вывода ${CONFIG.MIN_WITHDRAW} USDT`);
        }
        
        const fee = Math.max(CONFIG.WITHDRAW_FEE_MIN, amount * CONFIG.WITHDRAW_FEE_PERCENT);
        const totalAmount = amount + fee;
        
        // Check user balance
        const user = await User.findOne({ telegramId: userId }).session(session);
        
        if (!user) {
            throw new Error('User not found');
        }
        
        if (user.balance < totalAmount) {
            throw new Error('Недостаточно средств с учётом комиссии');
        }
        
        // Create check
        const checkResult = await cryptoBotAPI.createCheck('USDT', amount);
        
        if (!checkResult.success) {
            throw new Error(checkResult.error || 'Ошибка создания чека');
        }
        
        // Create withdraw record
        const withdraw = new Withdraw({
            userId,
            amount,
            fee,
            totalAmount,
            checkCode: checkResult.checkCode,
            checkId: checkResult.checkId,
            status: 'pending'
        });
        
        await withdraw.save({ session });
        
        // Update user balance
        user.balance -= totalAmount;
        user.totalWithdrawn += amount;
        await user.save({ session });
        
        // Save history
        const history = new GameHistory({
            userId,
            type: 'withdraw',
            win: -totalAmount,
            balanceBefore: user.balance + totalAmount,
            balanceAfter: user.balance,
            details: {
                checkCode: checkResult.checkCode,
                amount,
                fee
            }
        });
        await history.save({ session });
        
        await session.commitTransaction();
        session.endSession();
        
        res.json({
            success: true,
            checkCode: checkResult.checkCode,
            checkUrl: checkResult.botCheckUrl,
            amount,
            fee,
            totalAmount
        });
        
    } catch (error) {
        await session.abortTransaction();
        session.endSession();
        
        console.error('Create withdraw error:', error);
        res.status(400).json({ success: false, error: error.message });
    }
});

app.get('/api/history', authMiddleware, async (req, res) => {
    try {
        const { filter = 'all', limit = 20, offset = 0 } = req.query;
        const userId = req.userId;
        
        let query = { userId };
        
        if (filter === 'deposit') {
            query.type = 'deposit';
        } else if (filter === 'withdraw') {
            query.type = 'withdraw';
        } else if (filter === 'games') {
            query.type = 'spin';
        }
        
        const [history, total] = await Promise.all([
            GameHistory.find(query)
                .sort({ timestamp: -1 })
                .skip(parseInt(offset))
                .limit(parseInt(limit))
                .lean(),
            GameHistory.countDocuments(query)
        ]);
        
        const formattedHistory = history.map(item => ({
            type: item.type,
            amount: item.win || item.bet || 0,
            timestamp: item.timestamp,
            status: item.type === 'withdraw' ? 'pending' : 'completed'
        }));
        
        res.json({
            success: true,
            history: formattedHistory,
            total,
            hasMore: parseInt(offset) + parseInt(limit) < total
        });
        
    } catch (error) {
        console.error('History error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// Get user stats
app.get('/api/stats', authMiddleware, async (req, res) => {
    try {
        const userId = req.userId;
        
        const stats = await GameHistory.aggregate([
            { $match: { userId } },
            {
                $group: {
                    _id: null,
                    totalGames: { $sum: { $cond: [{ $eq: ['$type', 'spin'] }, 1, 0] } },
                    totalWins: { $sum: { $cond: [{ $gt: ['$win', 0] }, '$win', 0] } },
                    totalDeposited: { $sum: { $cond: [{ $eq: ['$type', 'deposit'] }, '$win', 0] } },
                    totalWithdrawn: { $sum: { $cond: [{ $eq: ['$type', 'withdraw'] }, { $multiply: ['$win', -1] }, 0] } }
                }
            }
        ]);
        
        res.json({
            success: true,
            stats: stats[0] || {
                totalGames: 0,
                totalWins: 0,
                totalDeposited: 0,
                totalWithdrawn: 0
            }
        });
        
    } catch (error) {
        console.error('Stats error:', error);
        res.status(500).json({ success: false, error: 'Server error' });
    }
});

// ==================== WEBHOOK HANDLERS ====================
app.post('/webhook/cryptobot', async (req, res) => {
    try {
        const { update_id, update_type, payload } = req.body;
        
        if (update_type === 'invoice_paid') {
            const { invoice_id, paid_anonymously } = payload;
            
            const invoice = await Invoice.findOne({ invoiceId: invoice_id.toString() });
            
            if (invoice && invoice.status === 'pending') {
                const session = await mongoose.startSession();
                session.startTransaction();
                
                try {
                    // Update invoice
                    invoice.status = 'paid';
                    invoice.paidAt = new Date();
                    invoice.paymentAmount = parseFloat(payload.paid_amount);
                    await invoice.save({ session });
                    
                    // Update user balance
                    const user = await User.findOne({ telegramId: invoice.userId }).session(session);
                    if (user) {
                        user.balance += invoice.amount;
                        user.totalDeposited += invoice.amount;
                        await user.save({ session });
                        
                        // Save history
                        const history = new GameHistory({
                            userId: invoice.userId,
                            type: 'deposit',
                            win: invoice.amount,
                            balanceBefore: user.balance - invoice.amount,
                            balanceAfter: user.balance,
                            details: { invoiceId: invoice_id, webhook: true }
                        });
                        await history.save({ session });
                    }
                    
                    await session.commitTransaction();
                    session.endSession();
                    
                    console.log(`✅ Invoice ${invoice_id} processed via webhook`);
                    
                } catch (error) {
                    await session.abortTransaction();
                    session.endSession();
                    throw error;
                }
            }
        }
        
        res.json({ success: true });
        
    } catch (error) {
        console.error('Webhook error:', error);
        res.status(500).json({ success: false, error: 'Webhook processing error' });
    }
});

// Cleanup expired invoices
app.get('/api/cleanup', async (req, res) => {
    try {
        const result = await Invoice.updateMany(
            { status: 'pending', expiresAt: { $lt: new Date() } },
            { status: 'expired' }
        );
        
        res.json({ success: true, cleaned: result.modifiedCount });
        
    } catch (error) {
        console.error('Cleanup error:', error);
        res.status(500).json({ success: false, error: 'Cleanup error' });
    }
});

// ==================== ROOT ROUTE ====================
app.get('/', (req, res) => {
    res.json({
        service: 'Purple Fortune Slots API',
        version: '1.0.0',
        environment: CONFIG.NODE_ENV,
        status: 'online',
        features: {
            mongodb: mongoose.connection.readyState === 1,
            cryptobot: CONFIG.CRYPTO_BOT_API_KEY ? 'real' : 'mock',
            telegram_validation: CONFIG.NODE_ENV === 'production'
        },
        endpoints: [
            'GET /api/balance',
            'POST /api/spin',
            'POST /api/create-invoice',
            'GET /api/check-invoice',
            'POST /api/create-withdraw',
            'GET /api/history',
            'GET /api/stats',
            'GET /health'
        ]
    });
});

// ==================== ERROR HANDLING ====================
app.use((err, req, res, next) => {
    console.error('Global error:', err.stack);
    res.status(500).json({ success: false, error: 'Internal server error' });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ success: false, error: 'Endpoint not found' });
});

// ==================== SERVER START ====================
(async () => {
    try {
        await connectWithRetry();
        
        app.listen(CONFIG.PORT, () => {
            console.log(`
✅ Purple Fortune API running on port ${CONFIG.PORT}
🌍 Environment: ${CONFIG.NODE_ENV}
💾 MongoDB: ${CONFIG.MONGODB_URI.includes('localhost') ? 'Local' : 'Atlas'}
🤖 CryptoBot: ${CONFIG.CRYPTO_BOT_API_KEY ? 'Real API' : 'Mock Mode'}
🌐 Frontend: ${CONFIG.FRONTEND_URL}
🔗 Webhook: ${CONFIG.FRONTEND_URL}/webhook/cryptobot
            `);
        });
        
        // Graceful shutdown
        process.on('SIGTERM', async () => {
            console.log('\n🛑 SIGTERM received. Shutting down gracefully...');
            await mongoose.connection.close();
            process.exit(0);
        });
        
        process.on('SIGINT', async () => {
            console.log('\n🛑 SIGINT received. Shutting down gracefully...');
            await mongoose.connection.close();
            process.exit(0);
        });
        
    } catch (error) {
        console.error('Failed to start server:', error);
        process.exit(1);
    }
})();

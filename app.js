require('dotenv').config();

const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const dbPool = require('./config/db');
const config = require('./config');
const ftp = require("basic-ftp");
const { Readable } = require('stream');
const multer = require('multer');
const redis = require('redis');
const RedisStore = require("connect-redis").default;
const crypto = require('crypto');
const { sendVerificationEmail, sendWelcomeEmail, sendPasswordResetEmail } = require('./config/mailer');

const app = express();

const storage = multer.memoryStorage();
const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('فقط فایل‌های تصویری مجاز هستند!'), false);
    }
};
const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: { fileSize: 1024 * 1024 * 5 } // 5MB
});

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const redisClient = redis.createClient({
    url: process.env.REDIS_URL
});
redisClient.connect().catch(console.error);

app.set('trust proxy', 1);

app.use((req, res, next) => {
    req.redisClient = redisClient;
    next();
});

app.use(session({
    store: new RedisStore({ client: redisClient }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 * 31, // 31 days
        sameSite: 'none'
    }
}));

app.use((req, res, next) => {
    res.locals.user = req.session.user || null;
    res.locals.MAIN_BOT_USERNAME = process.env.MAIN_BOT_USERNAME || 'YOUR_BOT_USERNAME';
    res.locals.READER_BASE_URL = process.env.READER_BASE_URL || 'https://read.targo.fun';
    
    if (req.session.success_message) {
        res.locals.success_message = req.session.success_message;
        delete req.session.success_message;
    }
    if (req.session.error_message) {
        res.locals.error_message = req.session.error_message;
        delete req.session.error_message;
    }
    
    next();
});

app.use((req, res, next) => {
    const originalRender = res.render;
    res.render = function (view, options, callback) {
        this.setHeader('Content-Type', 'text/html; charset=utf-8');
        originalRender.call(this, view, options, callback);
    };
    next();
});

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const isAuthenticated = (req, res, next) => {
    if (req.session.user) { return next(); }
    res.redirect(`/login?redirect=${encodeURIComponent(req.originalUrl)}`);
};

app.get('/', async (req, res) => {
  try {
    const result = await dbPool.query("SELECT id, title, cover_image_url, status FROM mangas ORDER BY created_at DESC, id DESC LIMIT 12");
    res.render('home', { pageTitle: 'صفحه اصلی', recentMangas: result.rows });
  } catch (error) {
    console.error("Error fetching homepage mangas:", error);
    res.render('home', { pageTitle: 'صفحه اصلی', recentMangas: [] });
  }
});

app.get('/mangas', async (req, res) => {
    try {
        const page = parseInt(req.query.p) || 1;
        const limit = 30;
        const offset = (page - 1) * limit;

        const { search, status, sort_by, genres } = req.query;
        let whereClauses = [];
        let queryParams = [];
        let paramIndex = 1;

        if (search) {
            whereClauses.push(`(m.title ILIKE $${paramIndex} OR m.author ILIKE $${paramIndex + 1} OR m.artist ILIKE $${paramIndex + 2})`);
            const searchTerm = `%${search}%`;
            queryParams.push(searchTerm, searchTerm, searchTerm);
            paramIndex += 3;
        }
        if (status) {
            whereClauses.push(`m.status = $${paramIndex++}`);
            queryParams.push(status);
        }
        if (genres && genres.length > 0) {
            const genreList = Array.isArray(genres) ? genres : [genres];
            whereClauses.push(`m.id IN (SELECT manga_id FROM manga_genres WHERE genre_id = ANY($${paramIndex++}))`);
            queryParams.push(genreList);
        }

        const whereString = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';

        let orderByString = 'ORDER BY m.updated_at DESC';
        switch (sort_by) {
            case 'created_at_desc': orderByString = 'ORDER BY m.created_at DESC'; break;
            case 'title_asc': orderByString = 'ORDER BY m.title ASC'; break;
            case 'view_count_desc': orderByString = 'ORDER BY m.view_count DESC'; break;
        }

        const countQuery = `SELECT COUNT(DISTINCT m.id) as total FROM mangas m ${whereString}`;
        const countResult = await dbPool.query(countQuery, queryParams);
        const totalItems = countResult.rows[0].total;
        const totalPages = Math.ceil(totalItems / limit);

        const mangasQuery = `
            SELECT 
                m.id, m.title, m.cover_image_url, m.status, m.view_count,
                (SELECT STRING_AGG(c.name, ' و ') FROM channels c JOIN manga_channels mc ON c.id = mc.channel_id WHERE mc.manga_id = m.id) AS source_channel_name,
                (SELECT ch.chapter_number FROM chapters ch WHERE ch.manga_id = m.id ORDER BY CAST(REPLACE(ch.chapter_number, '-', '.') AS NUMERIC(10,2)) DESC, id DESC LIMIT 1) as latest_chapter_number
            FROM mangas m
            ${whereString}
            ${orderByString}
            LIMIT $${paramIndex++} OFFSET $${paramIndex++}
        `;
        const mangasResult = await dbPool.query(mangasQuery, [...queryParams, limit, offset]);

        const allGenresResult = await dbPool.query("SELECT id, name FROM genres ORDER BY name");

        res.render('all-mangas', {
            pageTitle: 'همه مانگاها',
            mangas: mangasResult.rows,
            totalPages,
            currentPage: page,
            currentFilters: { search: search || '', status: status || '', sort_by: sort_by || 'updated_at_desc', genres: genres ? (Array.isArray(genres) ? genres : [genres]) : [] },
            allGenres: allGenresResult.rows
        });

    } catch (error) {
        console.error("Failed to fetch mangas list:", error);
        res.status(500).send("خطا در بارگذاری لیست مانگاها.");
    }
});

const isEmail = (input) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);
const isPhone = (input) => /^[0-9\+]{10,15}$/.test(input);

app.get('/auth', async (req, res) => {
    const { state, token, identifier, error, success_message } = req.query;

    if (state === 'reset_password') {
        if (!token) {
            return res.render('auth', { pageTitle: 'خطا', state: 'message', error: 'توکن بازنشانی نامعتبر است.' });
        }
        try {
            const usersResult = await dbPool.query("SELECT id FROM users WHERE password_reset_token = $1 AND password_reset_expires > NOW()", [token]);
            if (usersResult.rows.length === 0) {
                return res.render('auth', { pageTitle: 'خطا', state: 'message', error: 'توکن بازنشانی نامعتبر است یا منقضی شده است.' });
            }
            return res.render('auth', { pageTitle: 'بازنشانی رمز عبور', state: 'reset_password', token });
        } catch (dbError) {
            console.error("DB Error on reset GET:", dbError);
            return res.status(500).send("خطای سرور");
        }
    }
    
    res.render('auth', { 
        pageTitle: 'ورود یا ثبت‌نام',
        state: state || 'initial',
        token: token || '',
        identifier: identifier || '',
        error: error || null,
        message: success_message || null,
        redirect: req.query.redirect || '/'
    });
});

app.get('/login', (req, res) => res.redirect(`/auth?redirect=${encodeURIComponent(req.query.redirect || '/')}`));
app.get('/register', (req, res) => res.redirect(`/auth?redirect=${encodeURIComponent(req.query.redirect || '/')}`));

app.post('/auth', async (req, res) => {
    const { identifier, password, app_username, state, redirect, token, confirm_password } = req.body;

    try {
        if (state === 'initial') {
            const usersResult = await dbPool.query("SELECT id FROM users WHERE email = $1 OR phone_number = $2 OR app_username = $3", [identifier, identifier, identifier]);
            if (usersResult.rows.length > 0) {
                return res.render('auth', { state: 'login', identifier, redirect, pageTitle: 'ورود' });
            } else {
                return res.render('auth', { state: 'register', identifier, redirect, pageTitle: 'ایجاد حساب' });
            }
        }

        if (state === 'login') {
            const usersResult = await dbPool.query("SELECT * FROM users WHERE email = $1 OR phone_number = $2 OR app_username = $3", [identifier, identifier, identifier]);
            const user = usersResult.rows[0];
            if (!user || !(await bcrypt.compare(password, user.password_hash))) {
                return res.render('auth', { error: 'رمز عبور اشتباه است.', state: 'login', identifier, redirect, pageTitle: 'ورود' });
            }
    
            const userId = user.id;
            const userSessionsKey = `user:${userId}:sessions`;
            const sessionIds = await req.redisClient.sMembers(userSessionsKey);

            if (sessionIds && sessionIds.length > 0) {
                const pipeline = req.redisClient.multi();
                sessionIds.forEach(sessionId => {
                    pipeline.del(`sess:${sessionId}`); 
                });
                await pipeline.exec();
            }
            await req.redisClient.del(userSessionsKey);
            
            req.session.user = { id: userId, app_username: user.app_username, telegram_id: user.telegram_id, profile_image_url: user.profile_image_url };
    
            return req.session.save(async (err) => {
                if (err) return res.status(500).send('خطای سرور');
                await req.redisClient.sAdd(userSessionsKey, req.session.id);
                res.redirect(redirect || '/');
            });
        }

        if (state === 'register') {
            const existingUserResult = await dbPool.query("SELECT id FROM users WHERE app_username = $1", [app_username]);
            if (existingUserResult.rows.length > 0) {
                return res.render('auth', { error: 'این نام کاربری قبلاً استفاده شده است.', state: 'register', identifier, app_username, redirect, pageTitle: 'ایجاد حساب' });
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            let email = isEmail(identifier) ? identifier : null;
            let phone_number = isPhone(identifier) ? identifier : null;
            let emailToken = email ? crypto.randomBytes(32).toString('hex') : null;
            
            const result = await dbPool.query(
                "INSERT INTO users (app_username, password_hash, email, phone_number, email_verification_token) VALUES ($1, $2, $3, $4, $5) RETURNING id",
                [app_username, hashedPassword, email, phone_number, emailToken]
            );
            if (email && emailToken) {
                await sendWelcomeEmail(email, emailToken);
            }
            req.session.user = { id: result.rows[0].id, app_username, telegram_id: null, profile_image_url: null };
            return req.session.save(err => {
                if (err) return res.status(500).send('خطای سرور');
                req.session.success_message = phone_number ? 'حساب شما با موفقیت ساخته شد! لطفاً ایمیل خود را در بخش تنظیمات اضافه و تایید کنید.' : `حساب شما با موفقیت ساخته شد! ایمیل تایید به آدرس ${email} ارسال شد.`;
                res.redirect(redirect || '/account');
            });
        }

        if (state === 'forgot_password') {
            const usersResult = await dbPool.query("SELECT * FROM users WHERE email = $1", [identifier]);
            const user = usersResult.rows[0];
            if (user) {
                const resetToken = crypto.randomBytes(32).toString('hex');
                const expires = new Date(Date.now() + 3600000); // 1 hour
                await dbPool.query("UPDATE users SET password_reset_token = $1, password_reset_expires = $2 WHERE id = $3", [resetToken, expires, user.id]);
                await sendPasswordResetEmail(user.email, resetToken);
            }
            return res.render('auth', { state: 'message', message: 'اگر ایمیل شما در سیستم ما موجود باشد، لینک بازنشانی برایتان ارسال خواهد شد.', pageTitle: 'ایمیل ارسال شد' });
        }

        if (state === 'reset_password') {
            if (password !== confirm_password) {
                return res.render('auth', { error: 'رمزهای عبور مطابقت ندارند.', state: 'reset_password', token, pageTitle: 'بازنشانی رمز عبور' });
            }
            const usersResult = await dbPool.query("SELECT * FROM users WHERE password_reset_token = $1 AND password_reset_expires > NOW()", [token]);
            const user = usersResult.rows[0];
            if (!user) {
                return res.render('auth', { error: 'توکن بازنشانی نامعتبر است یا منقضی شده است.', state: 'message', pageTitle: 'خطا' });
            }
            const hashedPassword = await bcrypt.hash(password, 10);
            await dbPool.query("UPDATE users SET password_hash = $1, password_reset_token = NULL, password_reset_expires = NULL WHERE id = $2", [hashedPassword, user.id]);
            req.session.success_message = 'رمز عبور شما با موفقیت تغییر کرد. لطفاً وارد شوید.';
            return res.redirect('/auth');
        }

    } catch (error) {
        console.error("Auth process error:", error);
        res.render('auth', { error: 'خطای سرور. لطفاً دوباره تلاش کنید.', state: 'initial', redirect });
    }
});

app.get('/verify-email', async (req, res) => {
    try {
        const { token } = req.query;
        if (!token) return res.status(400).send('توکن تایید نامعتبر است.');
        const usersResult = await dbPool.query("SELECT id FROM users WHERE email_verification_token = $1", [token]);
        const user = usersResult.rows[0];
        if (!user) return res.status(400).send('این لینک تایید دیگر معتبر نیست یا قبلاً استفاده شده است.');
        await dbPool.query("UPDATE users SET email_verified_at = NOW(), email_verification_token = NULL WHERE id = $1", [user.id]);
        res.send('<h2>ایمیل شما با موفقیت تایید شد!</h2><p>اکنون می‌توانید وارد حساب کاربری خود شوید.</p><a href="/auth">رفتن به صفحه ورود</a>');
    } catch (error) {
        console.error("Email verification error:", error);
        res.status(500).send("خطا در پردازش تایید ایمیل.");
    }
});

app.get('/logout', async (req, res) => {
    if (req.session && req.session.user) {
        const userId = req.session.user.id;
        const sessionId = req.session.id;
        const userSessionsKey = `user:${userId}:sessions`;
        await req.redisClient.sRem(userSessionsKey, sessionId);
        
        req.session.destroy(err => {
            if (err) {
                console.error("Logout error:", err);
                return res.status(500).send("خطا در خروج از حساب کاربری.");
            }
            res.clearCookie('connect.sid');
            res.redirect('/');
        });
    } else {
        res.redirect('/');
    }
});

app.post('/account/resend-verification', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const usersResult = await dbPool.query("SELECT email, email_verification_token FROM users WHERE id = $1", [userId]);
        const user = usersResult.rows[0];

        if (user && user.email && !user.email_verified_at) {
            const token = user.email_verification_token || crypto.randomBytes(32).toString('hex');
            if (!user.email_verification_token) {
                await dbPool.query("UPDATE users SET email_verification_token = $1 WHERE id = $2", [token, userId]);
            }
            await sendVerificationEmail(user.email, token);
            res.json({ success: true, message: 'ایمیل تایید با موفقیت ارسال شد.' });
        } else {
            res.status(400).json({ success: false, message: 'ایمیل شما قبلاً تایید شده یا ثبت نشده است.' });
        }
    } catch (error) {
        console.error("Resend verification error:", error);
        res.status(500).json({ success: false, message: 'خطای سرور.' });
    }
});

app.get('/account', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.user.id;
        
        const userResult = await dbPool.query("SELECT * FROM users WHERE id = $1", [userId]);
        const userDetails = userResult.rows[0];
        
        const bookmarksResult = await dbPool.query(`
            SELECT 
                b.manga_id,
                b.notifications_enabled,
                m.title,
                m.cover_image_url,
                (SELECT c.name FROM channels c JOIN manga_channels mc ON c.id = mc.channel_id WHERE mc.manga_id = b.manga_id LIMIT 1) AS source_channel_name,
                (SELECT COUNT(ch.id) FROM chapters ch WHERE ch.manga_id = b.manga_id) as latest_chapter_number
            FROM bookmarks b
            JOIN mangas m ON b.manga_id = m.id
            WHERE b.user_id = $1
        `, [userId]);

        res.render('account', {
            pageTitle: 'حساب کاربری',
            userDetails,
            bookmarks: bookmarksResult.rows
        });
    } catch (error) {
        console.error("Failed to fetch account page:", error);
        res.status(500).send("خطا در بارگذاری صفحه حساب کاربری.");
    }
});

app.get('/connect-telegram', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const connectToken = crypto.randomBytes(20).toString('hex');
        await dbPool.query("UPDATE users SET telegram_connect_token = $1 WHERE id = $2", [connectToken, userId]);
        const botUsername = process.env.MAIN_BOT_USERNAME;
        const telegramUrl = `https://t.me/${botUsername}?start=${connectToken}`;
        res.redirect(telegramUrl);
    } catch (error) {
        console.error("Error generating telegram connect link:", error);
        res.status(500).send("خطا در ایجاد لینک اتصال.");
    }
});

app.post('/account/disconnect-telegram', isAuthenticated, async (req, res) => {
    try {
        await dbPool.query("UPDATE users SET telegram_id = NULL WHERE id = $1", [req.session.user.id]);
        req.session.user.telegram_id = null;
        req.session.save((err) => {
            if (err) {
                console.error("Session save error after telegram disconnect:", err);
                return res.status(500).json({ success: false, message: 'خطای سرور.' });
            }
            res.json({ success: true });
        });
    } catch (error) {
        console.error("Telegram disconnect error:", error);
        res.status(500).json({ success: false, message: 'خطای سرور.' });
    }
});

app.post('/bookmark/delete', isAuthenticated, async (req, res) => {
    try {
        const userId = req.session.user.id;
        const { mangaId } = req.body;
        
        if (!mangaId) {
            return res.status(400).json({ success: false, message: 'ID مانگا مشخص نشده است.' });
        }

        await dbPool.query("DELETE FROM bookmarks WHERE user_id = $1 AND manga_id = $2", [userId, mangaId]);
        res.json({ success: true });
    } catch (error) {
        console.error("Delete bookmark error:", error);
        res.status(500).json({ success: false, message: 'خطای سرور.' });
    }
});

app.post('/account/update-profile', isAuthenticated, upload.single('profile_image'), async (req, res) => {
    const userId = req.session.user.id;
    const { app_username, email, phone_number } = req.body;
    
    try {
        await dbPool.query(
            "UPDATE users SET app_username = $1, email = $2, phone_number = $3 WHERE id = $4",
            [app_username, email, phone_number, userId]
        );
        req.session.user.app_username = app_username;

        if (req.file) {
            const client = new ftp.Client();
            try {
                await client.access({
                    host: config.ftp.host,
                    user: config.ftp.user,
                    password: config.ftp.password,
                    secure: true,
                    secureOptions: { rejectUnauthorized: false }
                });

                const remoteDir = `/profiles/users/${userId}`;
                await client.ensureDir(remoteDir);
                const remoteFileName = `profile-${Date.now()}${path.extname(req.file.originalname)}`;
                const remotePath = `${remoteDir}/${remoteFileName}`; 
                const readableStream = Readable.from(req.file.buffer);
                await client.uploadFrom(readableStream, remotePath);
                const imageUrl = `${config.avatarPublicUrl}/${userId}/${remoteFileName}`;
                
                await dbPool.query("UPDATE users SET profile_image_url = $1 WHERE id = $2", [imageUrl, userId]);
                req.session.user.profile_image_url = imageUrl;
            } catch (ftpError) {
                console.error("FTP Upload Error:", ftpError);
                req.session.error_message = 'خطا در آپلود تصویر پروفایل.';
                return res.redirect('/account');
            } finally {
                if (!client.closed) client.close();
            }
        }

        req.session.success_message = 'پروفایل شما با موفقیت به‌روزرسانی شد.';
        req.session.save((err) => {
            if (err) {
                console.error("Session save error after profile update:", err);
            }
            res.redirect('/account');
        });

    } catch (error) {
        console.error("Failed to update profile:", error);
        req.session.error_message = 'خطا در به‌روزرسانی پروفایل.';
        res.redirect('/account');
    }
});

app.post('/bookmark/toggle', isAuthenticated, async (req, res) => {
    const { mangaId, action } = req.body;
    const userId = req.session.user.id;
    if (!mangaId || !action) { return res.status(400).json({ success: false, message: 'اطلاعات ناقص است.' }); }
    try {
        if (action === 'bookmark') { 
            await dbPool.query("INSERT INTO bookmarks (user_id, manga_id) VALUES ($1, $2) ON CONFLICT (user_id, manga_id) DO NOTHING", [userId, mangaId]);
            res.json({ success: true, status: 'bookmarked' }); 
        } else if (action === 'unbookmark') { 
            await dbPool.query("DELETE FROM bookmarks WHERE user_id = $1 AND manga_id = $2", [userId, mangaId]);
            res.json({ success: true, status: 'unbookmarked' }); 
        } else { 
            res.status(400).json({ success: false, message: 'عملیات نامعتبر است.' }); 
        }
    } catch (error) { 
        console.error("Error toggling bookmark:", error); 
        res.status(500).json({ success: false, message: 'خطای سرور.' }); 
    }
});

app.post('/bookmark/notification', isAuthenticated, async (req, res) => {
    const { mangaId, isEnabled } = req.body;
    const userId = req.session.user.id;
    if (!mangaId || typeof isEnabled === 'undefined') { return res.status(400).json({ success: false, message: 'اطلاعات ناقص است.' }); }
    try {
        const result = await dbPool.query("UPDATE bookmarks SET notifications_enabled = $1 WHERE user_id = $2 AND manga_id = $3", [isEnabled ? 1 : 0, userId, mangaId]);
        if (result.rowCount > 0) res.json({ success: true });
        else res.status(404).json({ success: false, message: 'بوکمارک یافت نشد.' });
    } catch (error) { 
        console.error("Error toggling notification:", error); 
        res.status(500).json({ success: false, message: 'خطای سرور.' }); 
    }
});

app.get('/api/home-data', async (req, res) => {
    try {
        const mangaQueryForCards = `
            SELECT
                m.id, m.title, m.cover_image_url, m.status, m.view_count,
                STRING_AGG(DISTINCT c.name, ' و ') AS source_channel_name,
                (SELECT ch.chapter_number FROM chapters ch WHERE ch.manga_id = m.id ORDER BY CAST(REPLACE(ch.chapter_number, '-', '.') AS NUMERIC(10,2)) DESC, id DESC LIMIT 1) as latest_chapter_number
            FROM mangas m
            LEFT JOIN manga_channels mc ON m.id = mc.manga_id
            LEFT JOIN channels c ON mc.channel_id = c.id
            GROUP BY m.id
        `;

        const mangaQueryForSlider = `
            SELECT
                m.id, m.title, m.cover_image_url, m.status, m.view_count, m.description,
                (SELECT c.name FROM channels c JOIN manga_channels mc ON c.id = mc.channel_id WHERE mc.manga_id = m.id LIMIT 1) AS source_channel_name,
                (SELECT c.profile_image_url FROM channels c JOIN manga_channels mc ON c.id = mc.channel_id WHERE mc.manga_id = m.id LIMIT 1) AS source_channel_profile_url,
                (SELECT ch.id FROM chapters ch WHERE ch.manga_id = m.id ORDER BY CAST(REPLACE(ch.chapter_number, '-', '.') AS NUMERIC(10,2)) ASC, id ASC LIMIT 1) as first_chapter_id,
                (SELECT ch.chapter_number FROM chapters ch WHERE ch.manga_id = m.id ORDER BY CAST(REPLACE(ch.chapter_number, '-', '.') AS NUMERIC(10,2)) DESC, id DESC LIMIT 1) as latest_chapter_number
            FROM mangas m
            GROUP BY m.id
        `;
        
        const recentMangasResult = await dbPool.query(`${mangaQueryForCards} ORDER BY m.created_at DESC, m.id DESC LIMIT 12`);
        const popularMangasResult = await dbPool.query(`${mangaQueryForSlider} ORDER BY m.view_count DESC, m.updated_at DESC LIMIT 12`);
        
        const latestUpdatesQuery = `
            SELECT
                m.id, m.title, m.cover_image_url, m.status, m.view_count,
                STRING_AGG(DISTINCT c.name, ' و ') AS source_channel_name,
                (SELECT ch.chapter_number FROM chapters ch WHERE ch.manga_id = m.id ORDER BY CAST(REPLACE(ch.chapter_number, '-', '.') AS NUMERIC(10,2)) DESC, id DESC LIMIT 1) as latest_chapter_number,
                (SELECT MAX(ch.id) FROM chapters ch WHERE ch.manga_id = m.id) AS latest_chapter_sort_key
            FROM mangas m
            LEFT JOIN manga_channels mc ON m.id = mc.manga_id
            LEFT JOIN channels c ON mc.channel_id = c.id
            WHERE EXISTS (SELECT 1 FROM chapters ch WHERE ch.manga_id = m.id)
            GROUP BY m.id
            ORDER BY latest_chapter_sort_key DESC
            LIMIT 12;
        `;
        const latestUpdatesResult = await dbPool.query(latestUpdatesQuery);
        
        const popularMangas = popularMangasResult.rows;
        if (popularMangas.length > 0) {
            for (let manga of popularMangas) {
                const genresResult = await dbPool.query("SELECT g.name FROM genres g JOIN manga_genres mg ON g.id = mg.genre_id WHERE mg.manga_id = $1", [manga.id]);
                manga.genres = genresResult.rows;
            }
        }
        
        const suggestedChannelsResult = await dbPool.query(
            `SELECT c.id, c.name, c.profile_image_url, c.telegram_handle,
             (SELECT COUNT(mc.manga_id) FROM manga_channels mc WHERE mc.channel_id = c.id) as manga_count
             FROM channels c
             ORDER BY manga_count DESC, c.created_at DESC LIMIT 10`
        );

        const mangaStatsResult = await dbPool.query("SELECT COUNT(*) as total FROM mangas");
        const chapterStatsResult = await dbPool.query("SELECT COUNT(*) as total FROM chapters");
        const channelStatsResult = await dbPool.query("SELECT COUNT(*) as total FROM channels");
        
        const siteStats = {
            mangaCount: mangaStatsResult.rows[0].total,
            chapterCount: chapterStatsResult.rows[0].total,
            channelCount: channelStatsResult.rows[0].total
        };

        res.json({
            success: true,
            recentMangas: recentMangasResult.rows,
            popularMangas: popularMangas,
            latestUpdates: latestUpdatesResult.rows,
            suggestedChannels: suggestedChannelsResult.rows,
            siteStats
        });

    } catch (error) {
        console.error("API Error fetching homepage data:", error);
        res.status(500).json({ success: false, message: "خطا در دریافت اطلاعات از سرور." });
    }
});

app.get('/channels', async (req, res) => {
    try {
        const page = parseInt(req.query.p) || 1;
        const limit = 24;
        const offset = (page - 1) * limit;

        const countResult = await dbPool.query("SELECT COUNT(id) as total FROM channels");
        const totalItems = countResult.rows[0].total;
        const totalPages = Math.ceil(totalItems / limit);

        const channelsQuery = `
            SELECT 
                c.id, c.name, c.profile_image_url, c.telegram_handle, c.bio,
                (SELECT COUNT(mc.manga_id) FROM manga_channels mc WHERE mc.channel_id = c.id) as manga_count
            FROM channels c 
            ORDER BY manga_count DESC, c.name ASC 
            LIMIT $1 OFFSET $2
        `;
        const channelsResult = await dbPool.query(channelsQuery, [limit, offset]);
        
        res.render('channels', {
            pageTitle: 'لیست کانال‌ها',
            channels: channelsResult.rows,
            currentPage: page,
            totalPages: totalPages
        });

    } catch (error) {
        console.error("Failed to fetch channels list:", error);
        res.status(500).send("خطا در بارگذاری لیست کانال‌ها.");
    }
});

app.get('/channel/:id', async (req, res) => {
    try {
        const channelId = parseInt(req.params.id);
        if (isNaN(channelId)) { return res.status(404).render('404', { pageTitle: 'یافت نشد' }); }

        const channelQuery = `
            SELECT 
                id, name, profile_image_url, telegram_handle, bio,
                (SELECT COUNT(mc.manga_id) FROM manga_channels mc WHERE mc.channel_id = channels.id) as manga_count
            FROM channels 
            WHERE id = $1
        `;
        const channelResult = await dbPool.query(channelQuery, [channelId]);
        const channel = channelResult.rows[0];

        if (!channel) { return res.status(404).render('404', { pageTitle: 'یافت نشد' }); }

        const mangasQuery = `
            SELECT m.id, m.title, m.cover_image_url 
            FROM mangas m
            JOIN manga_channels mc ON m.id = mc.manga_id
            WHERE mc.channel_id = $1 
            ORDER BY m.updated_at DESC
        `;
        const mangasResult = await dbPool.query(mangasQuery, [channelId]);

        res.render('channel-detail', {
            pageTitle: channel.name,
            channel,
            mangas: mangasResult.rows
        });
    } catch (error) {
        console.error(`Failed to fetch details for channel ID ${req.params.id}:`, error);
        res.status(500).send("خطا در بارگذاری اطلاعات کانال.");
    }
});

app.get('/manga/:id', async (req, res) => {
    const mangaId = parseInt(req.params.id);
    if (isNaN(mangaId)) { return res.status(404).render('404', { pageTitle: 'یافت نشد' }); }

    try {
        const mangaResult = await dbPool.query("SELECT id, title, cover_image_url, description, author, artist, status, release_year, view_count FROM mangas WHERE id = $1", [mangaId]);
        const manga = mangaResult.rows[0];
        if (!manga) { return res.status(404).render('404', { pageTitle: 'یافت نشد' }); }

        if (!req.session.viewedMangas) { req.session.viewedMangas = []; }
        if (!req.session.viewedMangas.includes(mangaId)) {
            dbPool.query("UPDATE mangas SET view_count = COALESCE(view_count, 0) + 1 WHERE id = $1", [mangaId])
                  .catch(err => console.error("Failed to update view count:", err));
            req.session.viewedMangas.push(mangaId);
        }

        const genresResult = await dbPool.query("SELECT g.name FROM genres g JOIN manga_genres mg ON g.id = mg.genre_id WHERE mg.manga_id = $1", [mangaId]);
        
        const chaptersResult = await dbPool.query(`
            SELECT id, chapter_number, title, upload_date
            FROM chapters 
            WHERE manga_id = $1
            ORDER BY CAST(REPLACE(chapter_number, '-', '.') AS NUMERIC(10,2)) DESC, id DESC
        `, [mangaId]);

        const sourceChannelsResult = await dbPool.query(`
            SELECT c.id, c.name, c.profile_image_url, 
                   (SELECT COUNT(*) FROM manga_channels mc_count WHERE mc_count.channel_id = c.id) as manga_count
            FROM channels c
            JOIN manga_channels mc ON c.id = mc.channel_id
            WHERE mc.manga_id = $1
        `, [mangaId]);

        let isBookmarked = false;
        let continueChapterId = null;
        let readChaptersSet = new Set();

        if (req.session.user) {
            const userId = req.session.user.id;
            const bookmarkResult = await dbPool.query("SELECT manga_id FROM bookmarks WHERE user_id = $1 AND manga_id = $2", [userId, mangaId]);
            isBookmarked = bookmarkResult.rows.length > 0;

            const historyResult = await dbPool.query(`
                SELECT urh.chapter_id FROM user_read_history urh
                WHERE urh.user_id = $1 AND EXISTS (SELECT 1 FROM chapters c WHERE c.id = urh.chapter_id AND c.manga_id = $2)
                ORDER BY urh.read_at DESC LIMIT 1
            `, [userId, mangaId]);
            if (historyResult.rows.length > 0) {
                continueChapterId = historyResult.rows[0].chapter_id;
            }

            const chapterIds = chaptersResult.rows.map(c => c.id);
            if (chapterIds.length > 0) {
                 const readHistoryResult = await dbPool.query("SELECT chapter_id FROM user_read_history WHERE user_id = $1 AND chapter_id = ANY($2::int[])", [userId, chapterIds]);
                 readChaptersSet = new Set(readHistoryResult.rows.map(r => r.chapter_id));
            }
        }
        
        const chapters = chaptersResult.rows.map(chapter => {
            const chapterNumber = parseFloat(chapter.chapter_number) || 0;
            return {
                ...chapter,
                thumbnail_url: manga.cover_image_url,
                is_locked: !req.session.user && chapterNumber > 10,
                is_read: req.session.user ? readChaptersSet.has(chapter.id) : false
            };
        });

        req.session.save((err) => {
            if (err) return res.status(500).send("خطا در پردازش نشست.");
            
            res.render('manga-detail', {
                pageTitle: manga.title,
                manga,
                genres: genresResult.rows,
                chapters,
                total_chapters_count: chapters.length,
                isBookmarked,
                continueChapterId,
                sourceChannels: sourceChannelsResult.rows,
                user: req.session.user,
                req: req
            });
        });
        
    } catch (error) {
        console.error(`Failed to fetch manga ID ${mangaId}:`, error);
        res.status(500).send("خطا در بارگذاری اطلاعات.");
    }
});

app.get('/api/manga/:id/chapters', async (req, res) => {
    try {
        const mangaId = parseInt(req.params.id);
        if (isNaN(mangaId)) { return res.status(400).json({ success: false, error: 'Invalid manga ID' }); }

        const mangaResult = await dbPool.query("SELECT cover_image_url FROM mangas WHERE id = $1", [mangaId]);
        const coverImageUrl = mangaResult.rows.length > 0 ? mangaResult.rows[0].cover_image_url : null;
        
        const page = parseInt(req.query.page) || 1;
        const sortOrder = req.query.sort === 'asc' ? 'ASC' : 'DESC';
        const limit = 50;
        const offset = (page - 1) * limit;

        const query = `SELECT id, chapter_number, title, upload_date FROM chapters WHERE manga_id = $1 ORDER BY CAST(REPLACE(chapter_number, '-', '.') AS NUMERIC(10,2)) ${sortOrder}, id ${sortOrder} LIMIT $2 OFFSET $3`;
        const chaptersResult = await dbPool.query(query, [mangaId, limit, offset]);

        let readChaptersSet = new Set();
        if (req.session.user) {
            const chapterIds = chaptersResult.rows.map(c => c.id);
            if (chapterIds.length > 0) {
                const readHistoryResult = await dbPool.query("SELECT chapter_id FROM user_read_history WHERE user_id = $1 AND chapter_id = ANY($2::int[])", [req.session.user.id, chapterIds]);
                readChaptersSet = new Set(readHistoryResult.rows.map(r => r.chapter_id));
            }
        }

        const chapters = chaptersResult.rows.map(chapter => {
            const chapterNumber = parseFloat(chapter.chapter_number);
            const is_locked = !req.session.user && chapterNumber > 10;
            const is_read = req.session.user ? readChaptersSet.has(chapter.id) : false;

            return { ...chapter, thumbnail_url: coverImageUrl, is_locked, is_read };
        });
        
        res.json(chapters);

    } catch (error) {
        console.error('API Error fetching chapters:', error);
        res.status(500).json({ success: false, error: 'Internal Server Error' });
    }
});

app.get('/api/manga/:id/comments', async (req, res) => {
    const mangaId = req.params.id;
    const sortBy = req.query.sort_by || 'newest';
    let orderByClause = '';
    switch (sortBy) {
        case 'oldest': orderByClause = 'c.created_at ASC'; break;
        case 'most_liked': orderByClause = 'c.likes DESC, c.created_at DESC'; break;
        default: orderByClause = 'c.created_at DESC'; break;
    }

    try {
        const commentsResult = await dbPool.query(`
            SELECT 
                c.id, c.parent_id, c.content, c.is_spoiler, c.is_pinned, c.likes, c.dislikes, c.created_at,
                u.id as user_id, u.app_username, u.profile_image_url, u.is_owner, u.is_admin
            FROM comments c
            JOIN users u ON c.user_id = u.id
            WHERE c.manga_id = $1 AND c.is_deleted = false
            ORDER BY c.is_pinned DESC, ${orderByClause}
        `, [mangaId]);
        
        const comments = commentsResult.rows;

        if (req.session.user) {
            const userId = req.session.user.id;
            const commentIds = comments.map(c => c.id);
            if (commentIds.length > 0) {
                const votesResult = await dbPool.query(
                    "SELECT comment_id, vote_type FROM comment_votes WHERE user_id = $1 AND comment_id = ANY($2::int[])",
                    [userId, commentIds]
                );
                const votesMap = new Map(votesResult.rows.map(v => [v.comment_id, v.vote_type]));
                comments.forEach(comment => {
                    comment.user_vote = votesMap.get(comment.id) || null;
                });
            }
        }

        const commentsById = new Map();
        comments.forEach(comment => {
            commentsById.set(comment.id, { ...comment, replies: [] });
        });

        const rootComments = [];
        comments.forEach(comment => {
            if (comment.parent_id && commentsById.has(comment.parent_id)) {
                commentsById.get(comment.parent_id).replies.push(commentsById.get(comment.id));
            } else {
                rootComments.push(commentsById.get(comment.id));
            }
        });

        res.json({ success: true, comments: rootComments });

    } catch (error) {
        console.error("Error fetching comments:", error);
        res.status(500).json({ success: false, message: "خطا در بارگذاری نظرات." });
    }
});

app.post('/api/comments', isAuthenticated, async (req, res) => {
    const { manga_id, content, parent_id, is_spoiler } = req.body;
    const user_id = req.session.user.id;

    if (!content || !manga_id) {
        return res.status(400).json({ success: false, message: "محتوای کامنت و شناسه مانگا الزامی است." });
    }

    try {
        const result = await dbPool.query(
            "INSERT INTO comments (manga_id, user_id, parent_id, content, is_spoiler) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            [manga_id, user_id, parent_id || null, content, is_spoiler ? true : false]
        );
        res.json({ success: true, commentId: result.rows[0].id });
    } catch (error) {
        console.error("Error posting comment:", error);
        res.status(500).json({ success: false, message: "خطا در ثبت کامنت." });
    }
});

app.post('/api/comments/:id/vote', isAuthenticated, async (req, res) => {
    const comment_id = req.params.id;
    const user_id = req.session.user.id;
    const { vote_type } = req.body;

    if (vote_type !== 'like' && vote_type !== 'dislike') {
        return res.status(400).json({ success: false, message: "نوع رأی نامعتبر است." });
    }

    try {
        await dbPool.query(
            `INSERT INTO comment_votes (user_id, comment_id, vote_type) VALUES ($1, $2, $3)
             ON CONFLICT (user_id, comment_id) DO UPDATE SET vote_type = $3`,
            [user_id, comment_id, vote_type]
        );

        await dbPool.query(`
            UPDATE comments SET 
            likes = (SELECT COUNT(*) FROM comment_votes WHERE comment_id = $1 AND vote_type = 'like'),
            dislikes = (SELECT COUNT(*) FROM comment_votes WHERE comment_id = $1 AND vote_type = 'dislike')
            WHERE id = $1
        `, [comment_id]);

        res.json({ success: true });
    } catch (error) {
        console.error("Error voting on comment:", error);
        res.status(500).json({ success: false, message: "خطا در ثبت رأی." });
    }
});

app.post('/api/comments/:id/report', isAuthenticated, async (req, res) => {
    const comment_id = req.params.id;
    const reporting_user_id = req.session.user.id;
    const { reason } = req.body;

    try {
        console.log(`--- Comment Report ---`);
        console.log(`Comment ID: ${comment_id}`);
        console.log(`Reported by User ID: ${reporting_user_id}`);
        console.log(`Reason: ${reason || 'No reason provided.'}`);
        console.log(`--------------------`);
        res.json({ success: true, message: 'گزارش با موفقیت ثبت شد.' });
    } catch (error) {
        console.error("Error processing report:", error);
        res.status(500).json({ success: false, message: "خطا در ثبت گزارش." });
    }
});

const isAdmin = (req, res, next) => {
    if (req.session.user && (req.session.user.is_admin || req.session.user.is_owner)) {
        return next();
    }
    res.status(403).json({ success: false, message: "دسترسی غیرمجاز." });
};

app.post('/api/comments/:id/pin', isAdmin, async (req, res) => {
    const { pin_status } = req.body;
    await dbPool.query("UPDATE comments SET is_pinned = $1 WHERE id = $2", [pin_status ? true : false, req.params.id]);
    res.json({ success: true });
});

app.delete('/api/comments/:id', isAdmin, async (req, res) => {
    await dbPool.query("UPDATE comments SET is_deleted = true, content = '[این کامنت توسط ادمین حذف شده است]' WHERE id = $1", [req.params.id]);
    res.json({ success: true });
});

module.exports = app;

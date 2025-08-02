// config/db.js

// 1. فراخوانی کتابخانه mysql2
const mysql = require('mysql2/promise');

// 2. اطلاعات اتصال به دیتابیس شما
// !! مهم: این اطلاعات را با مقادیر واقعی دیتابیس خود جایگزین کنید.
const dbConfig = {
  host: '178.162.234.76',           // معمولا localhost است اگر دیتابیس روی همان سرور باشد
  user: 'tarfun_mytargo',     // نام کاربری دیتابیس شما (از تصویر قبلی شما)
  password: 'jq2#H6i;n,yn', // <--- رمز عبور دیتابیس خود را اینجا وارد کنید
  database: 'tarfun_mytargo2',   // نام دیتابیس شما (از تصویر قبلی شما)
  waitForConnections: true,
  connectionLimit: 10,       // تعداد حداکثر اتصالات همزمان
  queueLimit: 0,
  connectTimeout: 10000
};

// 3. ایجاد یک connection pool
const pool = mysql.createPool(dbConfig);

// 4. یک تست ساده برای اطمینان از صحت اتصال (اختیاری اما مفید)
async function testConnection() {
  let connection;
  try {
    connection = await pool.getConnection();
    console.log('Successfully connected to the database.');
    // می‌توانید یک کوئری ساده هم برای تست اجرا کنید
    // const [rows] = await connection.query('SELECT 1');
    // console.log('Test query successful.');
  } catch (error) {
    console.error('Error connecting to the database:', error);
    // اگر اپلیکیشن به دلیل خطای اتصال نباید اجرا شود، می‌توانید فرآیند را متوقف کنید
    // process.exit(1); 
  } finally {
    if (connection) connection.release(); // آزاد کردن اتصال پس از تست
  }
}

// تست اتصال هنگام شروع اپلیکیشن
testConnection();

// 5. اکسپورت کردن pool برای استفاده در سایر بخش‌های اپلیکیشن
module.exports = pool;

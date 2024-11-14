const express = require('express');
const mysql = require('mysql');
const multer = require('multer');
const path = require('path');
const axios = require('axios'); // Оставьте это объявление только один раз
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser'); // Импортируйте body-parser
const jwt = require('jsonwebtoken');
const fs = require('fs');
const router = express.Router(); // Initialize router
const crypto = require('crypto');
const cors = require('cors'); // Импортируем cors
require('dotenv').config(); // Для загрузки переменных окружения из .env

const app = express(); // Создание приложения Express


// Используйте переменные окружения для Telegram
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT; // Correctly accessing the token
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;




  app.use(cors({
    origin: 'https://boodaikg.com',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    credentials: true
  }));
  
app.use(bodyParser.json());
const secretKey = 'ваш_секретный_ключ'; // Добавьте это перед использованием

// Настройка базы данных
const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});
app.get('/', (req, res) => {
    res.send('Сервер работает!'); // Ответ, который будет возвращён при GET запросе на '/'
});

// Проверка соединения с базой данных
db.connect(async (err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err.message);
        return;
    }
    console.log('Подключено к базе данных MySQL');

    // Проверка на наличие администратора
    const checkAdminQuery = 'SELECT * FROM users WHERE role = "admin"';
    db.query(checkAdminQuery, async (error, results) => {
        if (error) {
            console.error('Ошибка проверки администратора:', error);
            return;
        }

        if (results.length === 0) {
            // Если нет администратора, создаём нового
            const generatedUsername = 'admin'; // Можно сгенерировать случайный логин, если нужно
            const generatedPassword = crypto.randomBytes(8).toString('hex'); // Генерация случайного пароля
            const hashedPassword = await bcrypt.hash(generatedPassword, 10);

            // Генерация токена
            const generatedToken = crypto.randomBytes(32).toString('hex'); // Генерация случайного токена

            const insertAdminQuery = 'INSERT INTO users (username, email, password, role, token, phone, country, gender) VALUES (?, ?, ?, "admin", ?, ?, ?, ?)';
            db.query(insertAdminQuery, [generatedUsername, 'admin@example.com', hashedPassword, generatedToken, '1234567890', 'DefaultCountry', 'male'], (error) => {
                if (error) {
                    console.error('Ошибка при создании администратора:', error);
                    return;
                }
                console.log(`Администратор создан! Логин: ${generatedUsername}, Пароль: ${generatedPassword}`);
            });
        } else {
            console.log('Администратор уже существует');
        }
    });
});

// Настройка статической раздачи для загруженных изображений
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Настройка multer для загрузки файлов
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, './uploads/'); // Проверьте, что папка 'uploads/' существует
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + path.extname(file.originalname)); // Сохранение файла с уникальным именем
    },
});
const upload = multer({ storage });
// Add a product and prices with transaction handling
app.post('/api/products', upload.single('image'), (req, res) => {
    const { name, description, category, subCategory, price, priceSmall, priceMedium, priceLarge } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;

    // Log incoming data to verify it's received correctly
    console.log('Received data on server:', { name, description, category, subCategory, imageUrl });

    // Check for required fields
    if (!imageUrl) return res.status(400).json({ error: 'Изображение обязательно' });
    if (!category) return res.status(400).json({ error: 'Категория обязательна' });

    const productSql = 'INSERT INTO products (name, description, category, sub_category, image_url) VALUES (?, ?, ?, ?, ?)';
    const productValues = [name, description, category, subCategory, imageUrl];

    db.beginTransaction((err) => {
        if (err) return res.status(500).json({ error: 'Ошибка транзакции' });

        db.query(productSql, productValues, (err, result) => {
            if (err) return db.rollback(() => res.status(500).json({ error: 'Ошибка при добавлении продукта' }));

            const productId = result.insertId;
            const priceSql = 'INSERT INTO prices (product_id, price_small, price, price_medium, price_large) VALUES (?, ?, ?, ?, ?)';
            const priceValues = [productId, priceSmall, price, priceMedium, priceLarge];

            db.query(priceSql, priceValues, (err) => {
                if (err) return db.rollback(() => res.status(500).json({ error: 'Ошибка при добавлении цен' }));

                db.commit((err) => {
                    if (err) return db.rollback(() => res.status(500).json({ error: 'Ошибка подтверждения транзакции' }));
                    res.status(201).json({ message: 'Продукт и цены успешно добавлены!' });
                });
            });
        });
    });
});


  app.get('/api/products', (req, res) => {
    const sql = `
        SELECT 
            products.id,
            products.name,
            products.description,
            products.category,
            products.image_url,
            prices.price_small,
            prices.price_medium,
            prices.price_large,
            prices.price
        FROM 
            products
        LEFT JOIN 
            prices ON products.id = prices.product_id
    `;
    
    db.query(sql, (err, results) => {
        if (err) {
            console.error('Ошибка при запросе данных:', err.message);  // Log the error
            return res.status(500).json({ error: 'Ошибка при получении продуктов' });
        }

        console.log('Products retrieved:', results);  // Log results to confirm
        res.json(results);
    });
});

// Маршрут для входа администратора
app.post('/api/admin-login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: 'Необходимо указать имя пользователя и пароль.' });
    }

    const sql = 'SELECT * FROM users WHERE username = ?';
    db.query(sql, [username], async (err, results) => {
        if (err) {
            console.error('Ошибка базы данных:', err);
            return res.status(500).json({ message: 'Ошибка базы данных.' });
        }

        if (results.length === 0) {
            const newAdminPassword = Math.random().toString(36).slice(-8); // Генерация пароля
            const hashedPassword = await bcrypt.hash(newAdminPassword, 10);

            const insertSql = 'INSERT INTO users (username, password) VALUES (?, ?)';
            db.query(insertSql, [username, hashedPassword], (err, result) => {
                if (err) {
                    console.error('Ошибка создания администратора:', err);
                    return res.status(500).json({ message: 'Ошибка создания администратора.' });
                }

                const token = jwt.sign({ userId: result.insertId, username }, process.env.JWT_SECRET, {
                    expiresIn: '1h',
                });

                res.status(201).json({
                    message: 'Новый администратор создан.',
                    token,
                    userId: result.insertId,
                    username,
                    generatedPassword: newAdminPassword,
                });
            });
        } else {
            const admin = results[0];
            const validPassword = await bcrypt.compare(password, admin.password);

            if (!validPassword) {
                return res.status(401).json({ message: 'Неверный пароль.' });
            }

            const token = jwt.sign({ userId: admin.id, username }, process.env.JWT_SECRET, {
                expiresIn: '1h',
            });

            res.json({
                message: 'Вход выполнен успешно.',
                token,
                userId: admin.id,
                username,
            });
        }
    });
});

// Маршрут для удаления продукта
app.delete('/api/products/:id', (req, res) => {
    const productId = req.params.id;
    const sql = 'DELETE FROM products WHERE id = ?';
    db.query(sql, [productId], (err, result) => {
        if (err) {
            console.error('Ошибка базы данных:', err);
            return res.status(500).json({ error: 'Ошибка базы данных' });
        }
        res.json({ message: 'Продукт успешно удален' });
    });
});

// Определение маршрута /api/send-order
// Настройка маршрута для GET

app.get('/api/send-order', async (req, res) => {
    const orderDetails = JSON.parse(req.query.orderDetails);
    const deliveryDetails = JSON.parse(req.query.deliveryDetails);
    const cartItems = JSON.parse(req.query.cartItems);

    const orderText = `
      📦 Новый заказ:
      👤 Имя: ${orderDetails.name || 'Нет'}
      📞 Телефон: ${orderDetails.phone || 'Нет'}
      📝 Комментарии: ${orderDetails.comments || 'Нет'}
      
      📦 Доставка:
      🚚 Имя: ${deliveryDetails.name || 'Нет'}
      📞 Телефон: ${deliveryDetails.phone || 'Нет'}
      📍 Адрес: ${deliveryDetails.address || 'Нет'}
      📝 Комментарии: ${deliveryDetails.comments || 'Нет'}

      🛒 Товары:
      ${cartItems.map(item => `${item.name} - ${item.quantity} шт. по ${item.price} сом`).join('\n')}

      💰 Итого: ${cartItems.reduce((total, item) => total + item.price * item.quantity, 0)} сом
    `;

    try {
        await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
            chat_id: TELEGRAM_CHAT_ID,
            text: orderText,
        });

        res.status(200).json({ message: 'Заказ отправлен в Telegram' });

    } catch (error) {
        console.error("Ошибка при отправке заказа:", error.response ? error.response.data : error.message);
        res.status(500).json({ 
            message: 'Ошибка отправки заказа',
            error: error.response ? error.response.data : error.message 
        });
    }
});

app.listen(5000, () => {
    console.log('Сервер запущен на порту 5000');
});

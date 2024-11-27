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


// Данные для моков (mockData)
const mockData = {
    cartItems: [
      { id: 1, name: "Pizza Margherita", quantity: 2, price: 10 },
      { id: 2, name: "Pizza Pepperoni", quantity: 1, price: 12 },
    ],
  };

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

// Эндпоинт /api/data
app.get('/api/data', (req, res) => {
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
            console.error('Ошибка при запросе данных:', err.message); // Лог ошибки
            return res.status(500).json({ error: 'Ошибка при получении данных' });
        }

        res.json(results); // Возвращаем данные из базы
    });
});


// Обновление продукта
app.put('/api/products/:id', upload.single('image'), (req, res) => {
    const { name, description, category, subCategory, price, priceSmall, priceMedium, priceLarge } = req.body;
    const imageUrl = req.file ? `/uploads/${req.file.filename}` : null;
    const productId = req.params.id;
  
    const productSql = `
      UPDATE products 
      SET name = ?, description = ?, category = ?, sub_category = ?, image_url = COALESCE(?, image_url) 
      WHERE id = ?
    `;
    const productValues = [name, description, category, subCategory, imageUrl, productId];
  
    db.beginTransaction((err) => {
      if (err) return res.status(500).json({ error: 'Ошибка транзакции' });
  
      db.query(productSql, productValues, (err, result) => {
        if (err) return db.rollback(() => res.status(500).json({ error: 'Ошибка при обновлении продукта' }));
  
        const priceSql = `
          UPDATE prices 
          SET price_small = ?, price_medium = ?, price_large = ?, price = ?
          WHERE product_id = ?
        `;
        const priceValues = [priceSmall, priceMedium, priceLarge, price, productId];
  
        db.query(priceSql, priceValues, (err) => {
          if (err) return db.rollback(() => res.status(500).json({ error: 'Ошибка при обновлении цен' }));
  
          db.commit((err) => {
            if (err) return db.rollback(() => res.status(500).json({ error: 'Ошибка подтверждения транзакции' }));
            res.status(200).json({ message: 'Продукт и цены успешно обновлены!' });
          });
        });
      });
    });
  });
  

  app.get('/api/products/:id', (req, res) => {
    const productId = req.params.id;
  
    const sql = `
      SELECT 
        products.id,
        products.name,
        products.description,
        products.category,
        products.sub_category AS subCategory,
        products.image_url,
        prices.price_small AS priceSmall,
        prices.price_medium AS priceMedium,
        prices.price_large AS priceLarge,
        prices.price
      FROM 
        products
      LEFT JOIN 
        prices ON products.id = prices.product_id
      WHERE 
        products.id = ?
    `;
  
    db.query(sql, [productId], (err, results) => {
      if (err) {
        console.error('Ошибка при запросе продукта:', err.message);
        return res.status(500).json({ error: 'Ошибка при получении продукта' });
      }
  
      if (results.length === 0) {
        return res.status(404).json({ error: 'Продукт не найден' });
      }
  
      res.json(results[0]);
    });
  });
  

  // API для регистрации пользователя
  app.post('/api/register', async (req, res) => {
    const { firstName, lastName, phone, email, password } = req.body;

    if (!firstName || !lastName || !phone || !email || !password) {
        return res.status(400).json({ message: 'Заполните все поля' });
    }

    try {
        // Проверка существующего пользователя
        const [existingUser] = await new Promise((resolve, reject) => {
            db.query(
                'SELECT * FROM userskg WHERE email = ? OR phone = ?',
                [email, phone],
                (err, results) => (err ? reject(err) : resolve(results))
            );
        });

        if (existingUser) {
            return res.status(400).json({ message: 'Пользователь с таким email или телефоном уже существует' });
        }

        // Хэширование пароля
        const passwordHash = await bcrypt.hash(password, 10);

        // Сохранение нового пользователя и получение его user_id
        const userId = await new Promise((resolve, reject) => {
            db.query(
                'INSERT INTO userskg (first_name, last_name, phone, email, password_hash) VALUES (?, ?, ?, ?, ?)',
                [firstName, lastName, phone, email, passwordHash],
                (err, results) => (err ? reject(err) : resolve(results.insertId))
            );
        });

        const token = jwt.sign(
            { user_id: userId, email, phone }, // Данные, которые включаются в токен
            process.env.JWT_SECRET, // Секретный ключ из .env
            { expiresIn: '7d' } // Время жизни токена
        );
        
        // Сохранение токена в базе данных
        await new Promise((resolve, reject) => {
            db.query(
                'UPDATE userskg SET token = ? WHERE user_id = ?',
                [token, userId],
                (err) => (err ? reject(err) : resolve())
            );
        });

        // Успешный ответ
        res.status(201).json({
            message: 'Пользователь успешно зарегистрирован',
            token,
        });
    } catch (error) {
        console.error('Ошибка при регистрации пользователя:', error);
        res.status(500).json({ message: 'Ошибка сервера' });
    }
});
// API для получения информации о пользователе
// Защищенный маршрут для получения информации о пользователе
app.get('/api/user', (req, res) => {
    // Извлечение токена из заголовка Authorization
    const token = req.headers['authorization']?.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Необходим токен для доступа к этому ресурсу' });
    }

    // Проверка токена
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ message: 'Неверный токен' });
        }

        // SQL-запрос для получения данных пользователя
        const sql = `
        SELECT 
            user_id, 
            first_name AS username, 
            email, 
            phone, 
            balance 
        FROM userskg 
        WHERE user_id = ?
    `;
    
        db.query(sql, [decoded.user_id], (error, results) => {
            if (error) {
                console.error('Ошибка запроса к базе данных:', error);
                return res.status(500).json({ message: 'Ошибка сервера' });
            }

            if (results.length === 0) {
                return res.status(404).json({ message: 'Пользователь не найден' });
            }

            // Возврат данных пользователя
            const user = results[0];
            res.json({
                user_id: user.user_id,
                username: user.username,
                email: user.email,
                phone: user.phone,
                balance: user.balance,
            });
        });
    });
});
// API для входа пользователя
app.post('/api/login', (req, res) => {
    const { email, password } = req.body;

    // Проверка на наличие обязательных полей
    if (!email || !password) {
        return res.status(400).json({ message: 'Пожалуйста, введите email и пароль!' });
    }

    const sql = 'SELECT * FROM userskg WHERE email = ?';
    db.query(sql, [email], async (error, results) => {
        if (error) {
            console.error('Ошибка базы данных:', error);
            return res.status(500).json({ message: 'Ошибка сервера' });
        }

        if (results.length === 0) {
            return res.status(404).json({ message: 'Пользователь не найден!' });
        }

        const user = results[0];

        // Проверка наличия хэшированного пароля
        if (!user.password_hash) {
            console.error('Пароль отсутствует в базе данных для пользователя с email:', email);
            return res.status(500).json({ message: 'Ошибка сервера: пароль не найден.' });
        }

        try {
            // Сравнение паролей
            const isPasswordMatch = await bcrypt.compare(password, user.password_hash);

            if (!isPasswordMatch) {
                return res.status(400).json({ message: 'Неверный пароль!' });
            }

            // Если токен уже существует в базе данных, возвращаем его
            if (user.token) {
                return res.json({ message: 'Вход успешен', token: user.token, userId: user.user_id });
            }

            // Если токена нет, создаем новый, сохраняем и возвращаем
            const token = jwt.sign({ user_id: user.user_id }, secretKey, { expiresIn: '1h' });

            const updateTokenQuery = 'UPDATE userskg SET token = ? WHERE user_id = ?';
            db.query(updateTokenQuery, [token, user.user_id], (error) => {
                if (error) {
                    console.error('Ошибка при сохранении токена:', error);
                    return res.status(500).json({ message: 'Ошибка при сохранении токена' });
                }

                res.json({ message: 'Вход успешен', token, userId: user.user_id });
            });
        } catch (err) {
            console.error('Ошибка при сравнении пароля:', err);
            return res.status(500).json({ message: 'Ошибка сервера при проверке пароля.' });
        }
    });
});


  
app.listen(5000, () => {
    console.log('Сервер запущен на порту 5000');
});

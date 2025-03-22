const express = require("express");
const mysql = require("mysql2/promise");
const multer = require("multer");
const path = require("path");
const axios = require("axios");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const fs = require("fs").promises;
const crypto = require("crypto");
const cors = require("cors");
const winston = require("winston");
require("dotenv").config();
const nodemailer = require("nodemailer");

const app = express();

// Настройка логирования
const logger = winston.createLogger({
  level: "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: "error.log", level: "error" }),
    new winston.transports.File({ filename: "combined.log" }),
    new winston.transports.Console(),
  ],
});

// Переменные окружения
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const JWT_SECRET = process.env.JWT_SECRET || "your_default_secret_key";

// Проверка обязательных переменных окружения
const requiredEnvVars = [
  "DB_HOST",
  "DB_USER",
  "DB_PASSWORD",
  "DB_NAME",
  "TELEGRAM_BOT_TOKEN",
  "TELEGRAM_CHAT_ID",
  "EMAIL_USER",
  "EMAIL_PASS",
];
const missingEnvVars = requiredEnvVars.filter((varName) => !process.env[varName]);
if (missingEnvVars.length > 0) {
  logger.error(`Отсутствуют обязательные переменные окружения: ${missingEnvVars.join(", ")}`);
  process.exit(1);
}

// CORS настройки
app.use(cors({
  origin: ["https://boodaikg.com", "http://localhost:3000"],
  methods: ["GET", "POST", "PUT", "DELETE"],
  credentials: true,
}));

app.use(bodyParser.json());
app.use('/uploads', express.static('uploads')); // Раздача статических файлов

// Настройка Multer для загрузки файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) => cb(null, `${Date.now()}-${file.originalname}`),
});
const upload = multer({ storage });

// Создание папки uploads
(async () => {
  try {
    await fs.mkdir("uploads", { recursive: true });
    logger.info("Папка uploads создана или уже существует");
  } catch (err) {
    logger.error("Ошибка создания папки uploads:", err.message);
  }
})();

// Настройка базы данных
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  connectTimeout: 30000,
});

// Проверка подключения и создание администратора
(async () => {
  try {
    const connection = await db.getConnection();
    logger.info("Подключено к базе данных MySQL");
    connection.release();

    const [results] = await db.query('SELECT * FROM users WHERE role = "admin"');
    if (results.length === 0) {
      const username = "admin";
      const password = crypto.randomBytes(8).toString("hex");
      const hashedPassword = await bcrypt.hash(password, 10);
      await db.query(
        'INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, "admin")',
        [username, "admin@example.com", hashedPassword]
      );
      logger.info(`Администратор создан! Логин: ${username}, Пароль: ${password}`);
    } else {
      logger.info("Администратор уже существует");
    }
  } catch (err) {
    logger.error("Ошибка подключения к базе данных:", {
      message: err.message,
      stack: err.stack,
    });
    process.exit(1);
  }
})();

// Middleware для проверки токена
const authenticateToken = async (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    logger.warn("Токен отсутствует в запросе");
    return res.status(401).json({ message: "Требуется токен" });
  }
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    logger.error("Ошибка проверки токена:", error.message);
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ message: "Токен истёк" });
    }
    return res.status(403).json({ message: "Неверный токен" });
  }
};

// Middleware для проверки администратора
const authenticateAdmin = async (req, res, next) => {
  await authenticateToken(req, res, async () => {
    const [results] = await db.query("SELECT role FROM users WHERE id = ?", [req.user.userId]);
    if (results.length === 0 || results[0].role !== "admin") {
      logger.warn(`Доступ запрещён для userId: ${req.user.userId}`);
      return res.status(403).json({ message: "Доступ запрещён" });
    }
    next();
  });
};

// Базовый маршрут
app.get("/", (req, res) => {
  logger.info("Запрос к базовому маршруту");
  res.send("Сервер работает!");
});

// Health check
app.get("/health", (req, res) => {
  logger.info("Health check requested");
  res.status(200).json({ status: "OK", message: "Server is running" });
});

// Публичный маршрут для филиалов
app.get("/api/public/branches", async (req, res) => {
  try {
    const [results] = await db.query("SELECT * FROM branches WHERE status = 'active'");
    res.json(results);
  } catch (error) {
    logger.error("Ошибка при получении публичных филиалов:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Все филиалы (админ)
app.get("/api/branches", authenticateAdmin, async (req, res) => {
  try {
    const [results] = await db.query("SELECT * FROM branches");
    res.json(results);
  } catch (error) {
    logger.error("Ошибка при получении филиалов:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Добавление филиала
app.post("/api/branches", authenticateAdmin, async (req, res) => {
  const { name, address, phone, latitude, longitude, status } = req.body;
  if (!name || !address) {
    return res.status(400).json({ error: "Название и адрес обязательны" });
  }
  try {
    const normalizedStatus = status === "active" ? "active" : "inactive";
    const [result] = await db.query(
      "INSERT INTO branches (name, address, phone, latitude, longitude, status) VALUES (?, ?, ?, ?, ?, ?)",
      [name, address, phone || null, latitude || null, longitude || null, normalizedStatus]
    );
    res.status(201).json({ id: result.insertId, name, address, phone, latitude, longitude, status: normalizedStatus });
  } catch (error) {
    logger.error("Ошибка при добавлении филиала:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Обновление филиала
app.put("/api/branches/:id", authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, address, phone, latitude, longitude, status } = req.body;
  if (!name || !address) {
    return res.status(400).json({ error: "Название и адрес обязательны" });
  }
  try {
    const normalizedStatus = status === "active" ? "active" : "inactive";
    const [result] = await db.query(
      "UPDATE branches SET name = ?, address = ?, phone = ?, latitude = ?, longitude = ?, status = ? WHERE id = ?",
      [name, address, phone || null, latitude || null, longitude || null, normalizedStatus, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Филиал не найден" });
    }
    res.json({ id, name, address, phone, latitude, longitude, status: normalizedStatus });
  } catch (error) {
    logger.error("Ошибка при обновлении филиала:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Удаление филиала
app.delete("/api/branches/:id", authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query("DELETE FROM branches WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Филиал не найден" });
    }
    res.json({ message: "Филиал удалён" });
  } catch (error) {
    logger.error("Ошибка при удалении филиала:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Все категории (админ)
app.get("/api/categories", authenticateAdmin, async (req, res) => {
  try {
    const [results] = await db.query("SELECT * FROM categories ORDER BY priority ASC");
    res.json(results);
  } catch (error) {
    logger.error("Ошибка при получении категорий:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Добавление категории
app.post("/api/categories", authenticateAdmin, async (req, res) => {
  const { name, emoji, priority } = req.body;
  if (!name) {
    return res.status(400).json({ error: "Название обязательно" });
  }
  try {
    const [result] = await db.query(
      "INSERT INTO categories (name, emoji, priority) VALUES (?, ?, ?)",
      [name, emoji || null, priority || 0]
    );
    res.status(201).json({ id: result.insertId, name, emoji, priority });
  } catch (error) {
    logger.error("Ошибка при добавлении категории:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Обновление категории
app.put("/api/categories/:id", authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  const { name, emoji, priority } = req.body;
  if (!name) {
    return res.status(400).json({ error: "Название обязательно" });
  }
  try {
    const [result] = await db.query(
      "UPDATE categories SET name = ?, emoji = ?, priority = ? WHERE id = ?",
      [name, emoji || null, priority || 0, id]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Категория не найдена" });
    }
    res.json({ id, name, emoji, priority });
  } catch (error) {
    logger.error("Ошибка при обновлении категории:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Удаление категории
app.delete("/api/categories/:id", authenticateAdmin, async (req, res) => {
  const { id } = req.params;
  try {
    const [result] = await db.query("DELETE FROM categories WHERE id = ?", [id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Категория не найдена" });
    }
    res.json({ message: "Категория удалена" });
  } catch (error) {
    logger.error("Ошибка при удалении категории:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Публичные продукты филиала
app.get("/api/public/branches/:branchId/products", async (req, res) => {
  const { branchId } = req.params;
  try {
    const [results] = await db.query(
      `
      SELECT p.id, p.name, p.description, c.name as category, p.sub_category, p.image_url,
             bp.price_small, bp.price_medium, bp.price_large, bp.price, bp.status
      FROM products p
      JOIN categories c ON p.category_id = c.id
      JOIN branch_products bp ON p.id = bp.product_id
      WHERE bp.branch_id = ? AND bp.status = 'active'
      `,
      [branchId]
    );
    res.json(results);
  } catch (error) {
    logger.error("Ошибка при получении публичных продуктов:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Продукты филиала (админ)
app.get("/api/branches/:branchId/products", authenticateAdmin, async (req, res) => {
  const { branchId } = req.params;
  try {
    const [results] = await db.query(
      `
      SELECT p.id, p.name, p.description, c.name as category, p.sub_category, p.image_url,
             bp.price_small, bp.price_medium, bp.price_large, bp.price, bp.status
      FROM products p
      JOIN categories c ON p.category_id = c.id
      JOIN branch_products bp ON p.id = bp.product_id
      WHERE bp.branch_id = ?
      `,
      [branchId]
    );
    res.json(results);
  } catch (error) {
    logger.error("Ошибка при получении продуктов:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Добавление продукта
app.post("/api/branches/:branchId/products", authenticateAdmin, upload.single("image"), async (req, res) => {
  const { branchId } = req.params;
  const { name, description, category, subCategory, price, priceSmall, priceMedium, priceLarge } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : req.body.imageUrl;

  if (!name || !category || (!imageUrl && !req.body.imageUrl)) {
    return res.status(400).json({ error: "Название, категория и изображение обязательны" });
  }
  try {
    const [categoryResult] = await db.query("SELECT id FROM categories WHERE name = ?", [category]);
    if (categoryResult.length === 0) {
      return res.status(400).json({ error: "Категория не найдена" });
    }
    const categoryId = categoryResult[0].id;

    const [productResult] = await db.query(
      "INSERT INTO products (name, description, category_id, sub_category, image_url) VALUES (?, ?, ?, ?, ?)",
      [name, description || null, categoryId, subCategory || null, imageUrl]
    );
    const productId = productResult.insertId;

    await db.query(
      "INSERT INTO branch_products (branch_id, product_id, price_small, price_medium, price_large, price) VALUES (?, ?, ?, ?, ?, ?)",
      [branchId, productId, priceSmall || null, priceMedium || null, priceLarge || null, price || null]
    );

    res.status(201).json({ message: "Продукт добавлен", productId });
  } catch (error) {
    logger.error("Ошибка при добавлении продукта:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Обновление продукта
app.put("/api/branches/:branchId/products/:id", authenticateAdmin, upload.single("image"), async (req, res) => {
  const { branchId, id } = req.params;
  const { name, description, category, subCategory, price, priceSmall, priceMedium, priceLarge } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : req.body.imageUrl;

  if (!name || !category) {
    return res.status(400).json({ error: "Название и категория обязательны" });
  }
  try {
    const [categoryResult] = await db.query("SELECT id FROM categories WHERE name = ?", [category]);
    if (categoryResult.length === 0) {
      return res.status(400).json({ error: "Категория не найдена" });
    }
    const categoryId = categoryResult[0].id;

    if (req.file) {
      const [product] = await db.query("SELECT image_url FROM products WHERE id = ?", [id]);
      if (product.length > 0 && product[0].image_url) {
        const oldImagePath = path.join(__dirname, product[0].image_url);
        await fs.unlink(oldImagePath).catch(() => logger.warn(`Не удалось удалить старое изображение: ${oldImagePath}`));
      }
    }

    const [productResult] = await db.query(
      "UPDATE products SET name = ?, description = ?, category_id = ?, sub_category = ?, image_url = COALESCE(?, image_url) WHERE id = ?",
      [name, description || null, categoryId, subCategory || null, imageUrl, id]
    );
    if (productResult.affectedRows === 0) {
      return res.status(404).json({ error: "Продукт не найден" });
    }

    await db.query(
      "UPDATE branch_products SET price_small = ?, price_medium = ?, price_large = ?, price = ? WHERE branch_id = ? AND product_id = ?",
      [priceSmall || null, priceMedium || null, priceLarge || null, price || null, branchId, id]
    );

    res.json({ message: "Продукт обновлён" });
  } catch (error) {
    logger.error("Ошибка при обновлении продукта:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Удаление продукта
app.delete("/api/branches/:branchId/products/:id", authenticateAdmin, async (req, res) => {
  const { branchId, id } = req.params;
  try {
    await db.query("DELETE FROM branch_products WHERE branch_id = ? AND product_id = ?", [branchId, id]);
    const [countResult] = await db.query("SELECT COUNT(*) as count FROM branch_products WHERE product_id = ?", [id]);
    if (countResult[0].count === 0) {
      const [product] = await db.query("SELECT image_url FROM products WHERE id = ?", [id]);
      if (product.length > 0 && product[0].image_url) {
        const imagePath = path.join(__dirname, product[0].image_url);
        await fs.unlink(imagePath).catch(() => logger.warn(`Не удалось удалить изображение: ${imagePath}`));
      }
      await db.query("DELETE FROM products WHERE id = ?", [id]);
      res.json({ message: "Продукт полностью удалён" });
    } else {
      res.json({ message: "Продукт удалён из филиала" });
    }
  } catch (error) {
    logger.error("Ошибка при удалении продукта:", error.message);
    res.status(500).json({ error: "Ошибка сервера" });
  }
});

// Регистрация пользователя
app.post("/api/register", async (req, res) => {
  const { firstName, lastName, phone, email, password } = req.body;
  if (!firstName || !lastName || !phone || !email || !password) {
    return res.status(400).json({ message: "Заполните все поля" });
  }
  try {
    const [existingUser] = await db.query("SELECT * FROM userskg WHERE email = ? OR phone = ?", [email, phone]);
    if (existingUser.length > 0) {
      return res.status(400).json({ message: "Пользователь с таким email или телефоном уже существует" });
    }
    const confirmationCode = Math.floor(100000 + Math.random() * 900000);
    const hashedPassword = await bcrypt.hash(password, 10);
    await db.query(
      "INSERT INTO temp_users (first_name, last_name, phone, email, password_hash, confirmation_code) VALUES (?, ?, ?, ?, ?, ?)",
      [firstName, lastName, phone, email, hashedPassword, confirmationCode]
    );
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
    await transporter.sendMail({
      from: `"Boodai Pizza" <${process.env.EMAIL_USER}>`,
      to: email,
      subject: "Подтверждение регистрации",
      html: `<p>Ваш код подтверждения: <b>${confirmationCode}</b></p>`,
    });
    logger.info(`Код подтверждения отправлен: ${email}`);
    res.status(201).json({ message: "Код подтверждения отправлен на почту" });
  } catch (error) {
    logger.error("Ошибка при регистрации:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Подтверждение кода
app.post("/api/confirm-code", async (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ message: "Код обязателен" });
  }
  try {
    const [tempUser] = await db.query("SELECT * FROM temp_users WHERE confirmation_code = ?", [code]);
    if (tempUser.length === 0) {
      return res.status(400).json({ message: "Неверный код подтверждения" });
    }
    const [result] = await db.query(
      "INSERT INTO userskg (first_name, last_name, phone, email, password_hash) VALUES (?, ?, ?, ?, ?)",
      [tempUser[0].first_name, tempUser[0].last_name, tempUser[0].phone, tempUser[0].email, tempUser[0].password_hash]
    );
    const userId = result.insertId;
    await db.query("DELETE FROM temp_users WHERE confirmation_code = ?", [code]);
    const token = jwt.sign({ userId }, JWT_SECRET, { expiresIn: "24h" });
    await db.query("UPDATE userskg SET token = ? WHERE user_id = ?", [token, userId]);
    logger.info(`Пользователь подтверждён: ${userId}`);
    res.status(200).json({ message: "Подтверждение успешно", token, userId });
  } catch (error) {
    logger.error("Ошибка при подтверждении кода:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Вход пользователя
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Введите email и пароль" });
  }
  try {
    const [user] = await db.query("SELECT * FROM userskg WHERE email = ?", [email]);
    if (user.length === 0) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }
    const isPasswordMatch = await bcrypt.compare(password, user[0].password_hash);
    if (!isPasswordMatch) {
      return res.status(400).json({ message: "Неверный пароль" });
    }
    const token = jwt.sign({ userId: user[0].user_id }, JWT_SECRET, { expiresIn: "1h" });
    await db.query("UPDATE userskg SET token = ? WHERE user_id = ?", [token, user[0].user_id]);
    logger.info(`Пользователь вошёл: ${email}`);
    res.json({ message: "Вход успешен", token, userId: user[0].user_id });
  } catch (error) {
    logger.error("Ошибка входа:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Вход администратора
app.post("/api/admin-login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ message: "Введите имя пользователя и пароль" });
  }
  try {
    const [results] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
    if (results.length === 0) {
      return res.status(404).json({ message: "Администратор не найден" });
    }
    const admin = results[0];
    const validPassword = await bcrypt.compare(password, admin.password);
    if (!validPassword) {
      return res.status(401).json({ message: "Неверный пароль" });
    }
    const token = jwt.sign({ userId: admin.id }, JWT_SECRET, { expiresIn: "1h" });
    logger.info(`Администратор вошёл: ${username}`);
    res.json({ message: "Вход выполнен успешно", token, userId: admin.id });
  } catch (error) {
    logger.error("Ошибка входа администратора:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Информация о пользователе
app.get("/api/user", authenticateToken, async (req, res) => {
  try {
    const [results] = await db.query(
      "SELECT user_id, first_name AS username, email, phone, balance FROM userskg WHERE user_id = ?",
      [req.user.userId]
    );
    if (results.length === 0) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }
    res.json(results[0]);
  } catch (error) {
    logger.error("Ошибка запроса пользователя:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Все пользователи (админ)
app.get("/api/users", authenticateAdmin, async (req, res) => {
  try {
    const [results] = await db.query("SELECT * FROM userskg");
    res.json(results);
  } catch (error) {
    logger.error("Ошибка при запросе пользователей:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Удаление пользователя
app.delete("/api/users/:user_id", authenticateAdmin, async (req, res) => {
  const { user_id } = req.params;
  try {
    const [result] = await db.query("DELETE FROM userskg WHERE user_id = ?", [user_id]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }
    res.json({ message: "Пользователь удалён" });
  } catch (error) {
    logger.error("Ошибка при удалении пользователя:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Генерация промокода
const generatePromoCode = () => "PROMO-" + Math.random().toString(36).substr(2, 9).toUpperCase();

// Отправка промокода
app.post("/api/users/:user_id/promo", authenticateAdmin, async (req, res) => {
  const { user_id } = req.params;
  const { discount } = req.body;
  if (!discount || discount < 1 || discount > 100) {
    return res.status(400).json({ message: "Скидка должна быть от 1 до 100" });
  }
  try {
    const [user] = await db.query("SELECT email FROM userskg WHERE user_id = ?", [user_id]);
    if (user.length === 0) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }
    const promoCode = generatePromoCode();
    const now = new Date();
    await db.query(
      "UPDATE userskg SET promo_code = ?, promo_code_created_at = ?, discount = ? WHERE user_id = ?",
      [promoCode, now, discount, user_id]
    );
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });
    await transporter.sendMail({
      from: `"Boodai Pizza" <${process.env.EMAIL_USER}>`,
      to: user[0].email,
      subject: "Ваш промокод",
      html: `<p>Промокод: <b>${promoCode}</b>, Скидка: ${discount}%</p>`,
    });
    res.json({ promoCode, discount });
  } catch (error) {
    logger.error("Ошибка при отправке промокода:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Проверка промокода
app.post("/api/validate-promo", async (req, res) => {
  const { promoCode } = req.body;
  if (!promoCode) {
    return res.status(400).json({ message: "Промокод обязателен" });
  }
  try {
    const [results] = await db.query("SELECT * FROM userskg WHERE promo_code = ?", [promoCode]);
    if (results.length === 0) {
      return res.status(400).json({ message: "Неверный промокод" });
    }
    const { promo_code_created_at, discount } = results[0];
    const createdAt = new Date(promo_code_created_at);
    const expiryDate = new Date(createdAt.getTime() + 7 * 24 * 60 * 60 * 1000);
    if (new Date() > expiryDate) {
      return res.status(400).json({ message: "Промокод истёк" });
    }
    res.json({ discount });
  } catch (error) {
    logger.error("Ошибка при проверке промокода:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Отправка заказа в Telegram
app.post("/api/send-order", async (req, res) => {
  const { orderDetails, deliveryDetails, cartItems, discount, promoCode } = req.body;
  try {
    const total = cartItems.reduce((sum, item) => sum + item.originalPrice * item.quantity, 0);
    const discountedTotal = total * (1 - (discount || 0) / 100);
    const orderText = `
📦 *Новый заказ:*
👤 Имя: ${orderDetails.name || "Нет"}
📞 Телефон: ${orderDetails.phone || "Нет"}
📝 Комментарии: ${orderDetails.comments || "Нет"}

🚚 *Доставка:*
👤 Имя: ${deliveryDetails.name || "Нет"}
📞 Телефон: ${deliveryDetails.phone || "Нет"}
📍 Адрес: ${deliveryDetails.address || "Нет"}
📝 Комментарии: ${deliveryDetails.comments || "Нет"}

🛒 *Товары:*
${cartItems.map((item) => `- ${item.name} (${item.quantity} шт. по ${item.originalPrice} сом)`).join("\n")}

💰 Итоговая стоимость: ${total.toFixed(2)} сом
${promoCode ? `💸 Скидка (${discount}%): ${discountedTotal.toFixed(2)} сом` : "💸 Скидка не применена"}
💰 Итоговая сумма: ${discountedTotal.toFixed(2)} сом
    `;
    await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: orderText,
      parse_mode: "Markdown",
    });
    res.status(200).json({ message: "Заказ отправлен в Telegram" });
  } catch (error) {
    logger.error("Ошибка при отправке заказа:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  logger.info(`Сервер запущен на порту ${PORT}`);
});

app.on("error", (err) => {
  logger.error("Ошибка при запуске сервера:", err.message);
  process.exit(1);
});
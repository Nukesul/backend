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
app.use(
  cors({
    origin: ["https://boodaikg.com", "http://localhost:3000"],
    methods: ["GET", "POST", "PUT", "DELETE"],
    credentials: true,
  })
);

app.use(bodyParser.json());

// Настройка Multer для загрузки файлов
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname)),
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

// Проверка подключения к базе данных
(async () => {
  try {
    const connection = await db.getConnection();
    logger.info("Подключено к базе данных MySQL");
    connection.release();

    // Проверка наличия администратора
    const [results] = await db.query('SELECT * FROM users WHERE role = "admin"');
    if (results.length === 0) {
      const generatedUsername = "admin";
      const generatedPassword = crypto.randomBytes(8).toString("hex");
      const hashedPassword = await bcrypt.hash(generatedPassword, 10);
      const generatedToken = crypto.randomBytes(32).toString("hex");

      await db.query(
        'INSERT INTO users (username, email, password, role, token, phone, country, gender) VALUES (?, ?, ?, "admin", ?, ?, ?, ?)',
        [
          generatedUsername,
          "admin@example.com",
          hashedPassword,
          generatedToken,
          "1234567890",
          "DefaultCountry",
          "male",
        ]
      );
      logger.info(
        `Администратор создан! Логин: ${generatedUsername}, Пароль: ${generatedPassword}`
      );
    } else {
      logger.info("Администратор уже существует");
    }
  } catch (err) {
    logger.error("Ошибка подключения к базе данных:", {
      message: err.message,
      stack: err.stack,
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      database: process.env.DB_NAME,
    });
    process.exit(1);
  }
})();

// Middleware для проверки администратора
const authenticateAdmin = async (req, res, next) => {
  try {
    const token = req.headers["authorization"]?.split(" ")[1];
    if (!token) {
      logger.warn("Токен отсутствует в запросе");
      return res.status(401).json({ message: "Требуется токен" });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    const [results] = await db.query("SELECT role FROM users WHERE id = ?", [
      decoded.userId,
    ]);
    if (results.length === 0 || results[0].role !== "admin") {
      logger.warn(`Доступ запрещён для userId: ${decoded.userId}`);
      return res.status(403).json({ message: "Доступ запрещён" });
    }
    req.user = decoded;
    next();
  } catch (err) {
    logger.error("Ошибка проверки токена:", err.message);
    return res.status(403).json({ message: "Неверный токен" });
  }
};

// Базовый маршрут
app.get("/", (req, res) => {
  logger.info("Запрос к базовому маршруту");
  res.send("Сервер работает!");
});

// Health check endpoint
app.get("/health", (req, res) => {
  logger.info("Health check requested");
  res.status(200).json({ status: "OK", message: "Server is running" });
});

// Публичный маршрут для получения всех филиалов
app.get("/api/public/branches", async (req, res) => {
  try {
    logger.info("Запрос к /api/public/branches");
    const [results] = await db.query("SELECT * FROM branches WHERE status = 'active'");
    res.json(results);
  } catch (err) {
    logger.error("Ошибка при получении филиалов (публичный маршрут):", err.message);
    res.status(500).json({ error: "Ошибка при получении филиалов" });
  }
});

// Получение всех филиалов (админ)
app.get("/api/branches", authenticateAdmin, async (req, res) => {
  try {
    logger.info("Запрос к /api/branches");
    const [results] = await db.query("SELECT * FROM branches");
    res.json(results);
  } catch (err) {
    logger.error("Ошибка при получении филиалов:", err.message);
    res.status(500).json({ error: "Ошибка при получении филиалов" });
  }
});

// Добавление нового филиала
app.post("/api/branches", authenticateAdmin, async (req, res) => {
  const { name, address, phone, latitude, longitude, status } = req.body;

  if (!name || !address) {
    logger.warn("Название и адрес обязательны");
    return res.status(400).json({ error: "Название и адрес обязательны" });
  }

  if (latitude && (latitude < -90 || latitude > 90)) {
    logger.warn("Неверная широта");
    return res.status(400).json({ error: "Широта должна быть в диапазоне от -90 до 90" });
  }
  if (longitude && (longitude < -180 || longitude > 180)) {
    logger.warn("Неверная долгота");
    return res.status(400).json({ error: "Долгота должна быть в диапазоне от -180 до 180" });
  }

  const normalizedStatus = status === "active" ? "active" : "inactive";
  try {
    const [result] = await db.query(
      "INSERT INTO branches (name, address, phone, latitude, longitude, status) VALUES (?, ?, ?, ?, ?, ?)",
      [name, address, phone || null, latitude || null, longitude || null, normalizedStatus]
    );
    logger.info(`Филиал добавлен: ${name}`);
    res.status(201).json({
      id: result.insertId,
      name,
      address,
      phone,
      latitude,
      longitude,
      status: normalizedStatus,
    });
  } catch (err) {
    logger.error("Ошибка при добавлении филиала:", err.message);
    res.status(500).json({ error: "Ошибка при добавлении филиала" });
  }
});

// Обновление филиала
app.put("/api/branches/:id", authenticateAdmin, async (req, res) => {
  const branchId = req.params.id;
  const { name, address, phone, latitude, longitude, status } = req.body;

  if (!name || !address) {
    logger.warn("Название и адрес обязательны");
    return res.status(400).json({ error: "Название и адрес обязательны" });
  }

  if (latitude && (latitude < -90 || latitude > 90)) {
    logger.warn("Неверная широта");
    return res.status(400).json({ error: "Широта должна быть в диапазоне от -90 до 90" });
  }
  if (longitude && (longitude < -180 || longitude > 180)) {
    logger.warn("Неверная долгота");
    return res.status(400).json({ error: "Долгота должна быть в диапазоне от -180 до 180" });
  }

  const normalizedStatus = status === "active" ? "active" : "inactive";
  try {
    const [result] = await db.query(
      "UPDATE branches SET name = ?, address = ?, phone = ?, latitude = ?, longitude = ?, status = ? WHERE id = ?",
      [name, address, phone || null, latitude || null, longitude || null, normalizedStatus, branchId]
    );
    if (result.affectedRows === 0) {
      logger.warn(`Филиал не найден: ${branchId}`);
      return res.status(404).json({ error: "Филиал не найден" });
    }
    logger.info(`Филиал обновлён: ${branchId}`);
    res.json({
      id: branchId,
      name,
      address,
      phone,
      latitude,
      longitude,
      status: normalizedStatus,
    });
  } catch (err) {
    logger.error("Ошибка при обновлении филиала:", err.message);
    res.status(500).json({ error: "Ошибка при обновлении филиала" });
  }
});

// Удаление филиала
app.delete("/api/branches/:id", authenticateAdmin, async (req, res) => {
  const branchId = req.params.id;
  try {
    const [result] = await db.query("DELETE FROM branches WHERE id = ?", [branchId]);
    if (result.affectedRows === 0) {
      logger.warn(`Филиал не найден: ${branchId}`);
      return res.status(404).json({ error: "Филиал не найден" });
    }
    logger.info(`Филиал удалён: ${branchId}`);
    res.json({ message: "Филиал успешно удалён" });
  } catch (err) {
    logger.error("Ошибка при удалении филиала:", err.message);
    res.status(500).json({ error: "Ошибка при удалении филиала" });
  }
});

// Получение всех категорий
app.get("/api/categories", authenticateAdmin, async (req, res) => {
  try {
    logger.info("Запрос к /api/categories");
    const [results] = await db.query("SELECT * FROM categories ORDER BY priority ASC");
    res.json(results);
  } catch (err) {
    logger.error("Ошибка при получении категорий:", err.message);
    res.status(500).json({ error: "Ошибка при получении категорий" });
  }
});

// Добавление новой категории
app.post("/api/categories", authenticateAdmin, async (req, res) => {
  const { name, emoji, priority } = req.body;

  if (!name) {
    logger.warn("Название категории обязательно");
    return res.status(400).json({ error: "Название обязательно" });
  }

  try {
    const [result] = await db.query(
      "INSERT INTO categories (name, emoji, priority) VALUES (?, ?, ?)",
      [name, emoji || null, priority || 0]
    );
    logger.info(`Категория добавлена: ${name}`);
    res.status(201).json({
      id: result.insertId,
      name,
      emoji,
      priority,
    });
  } catch (err) {
    logger.error("Ошибка при добавлении категории:", err.message);
    res.status(500).json({ error: "Ошибка при добавлении категории" });
  }
});

// Обновление категории
app.put("/api/categories/:id", authenticateAdmin, async (req, res) => {
  const categoryId = req.params.id;
  const { name, emoji, priority } = req.body;

  if (!name) {
    logger.warn("Название категории обязательно");
    return res.status(400).json({ error: "Название обязательно" });
  }

  try {
    const [result] = await db.query(
      "UPDATE categories SET name = ?, emoji = ?, priority = ? WHERE id = ?",
      [name, emoji || null, priority || 0, categoryId]
    );
    if (result.affectedRows === 0) {
      logger.warn(`Категория не найдена: ${categoryId}`);
      return res.status(404).json({ error: "Категория не найдена" });
    }
    logger.info(`Категория обновлена: ${categoryId}`);
    res.json({
      id: categoryId,
      name,
      emoji,
      priority,
    });
  } catch (err) {
    logger.error("Ошибка при обновлении категории:", err.message);
    res.status(500).json({ error: "Ошибка при обновлении категории" });
  }
});

// Удаление категории
app.delete("/api/categories/:id", authenticateAdmin, async (req, res) => {
  const categoryId = req.params.id;
  try {
    const [result] = await db.query("DELETE FROM categories WHERE id = ?", [categoryId]);
    if (result.affectedRows === 0) {
      logger.warn(`Категория не найдена: ${categoryId}`);
      return res.status(404).json({ error: "Категория не найдена" });
    }
    logger.info(`Категория удалена: ${categoryId}`);
    res.json({ message: "Категория успешно удалена" });
  } catch (err) {
    logger.error("Ошибка при удалении категории:", err.message);
    res.status(500).json({ error: "Ошибка при удалении категории" });
  }
});

// Публичный маршрут для получения продуктов филиала
app.get("/api/public/branches/:branchId/products", async (req, res) => {
  const branchId = req.params.branchId;
  try {
    logger.info(`Запрос к /api/public/branches/${branchId}/products`);
    const [results] = await db.query(
      `
      SELECT 
        p.id,
        p.name,
        p.description,
        p.category_id,
        c.name as category,
        p.sub_category,
        p.image_url,
        bp.price_small,
        bp.price_medium,
        bp.price_large,
        bp.price,
        bp.status
      FROM 
        products p
      JOIN 
        categories c ON p.category_id = c.id
      JOIN 
        branch_products bp ON p.id = bp.product_id
      WHERE 
        bp.branch_id = ? AND bp.status = 'active'
      `,
      [branchId]
    );
    res.json(results);
  } catch (err) {
    logger.error("Ошибка при запросе данных (публичный маршрут):", err.message);
    res.status(500).json({ error: "Ошибка при получении продуктов" });
  }
});

// Получение всех продуктов для конкретного филиала (админ)
app.get("/api/branches/:branchId/products", authenticateAdmin, async (req, res) => {
  const branchId = req.params.branchId;
  try {
    logger.info(`Запрос к /api/branches/${branchId}/products`);
    const [results] = await db.query(
      `
      SELECT 
        p.id,
        p.name,
        p.description,
        p.category_id,
        c.name as category,
        p.sub_category,
        p.image_url,
        bp.price_small,
        bp.price_medium,
        bp.price_large,
        bp.price,
        bp.status
      FROM 
        products p
      JOIN 
        categories c ON p.category_id = c.id
      JOIN 
        branch_products bp ON p.id = bp.product_id
      WHERE 
        bp.branch_id = ?
      `,
      [branchId]
    );
    res.json(results);
  } catch (err) {
    logger.error("Ошибка при запросе данных:", err.message);
    res.status(500).json({ error: "Ошибка при получении продуктов" });
  }
});

// Добавление нового продукта для филиала
app.post("/api/branches/:branchId/products", authenticateAdmin, upload.single("image"), async (req, res) => {
  const branchId = req.params.branchId;
  const { name, description, category, subCategory, price, priceSmall, priceMedium, priceLarge } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : req.body.imageUrl;

  if (!name || !category) {
    logger.warn("Поля name и category обязательны");
    return res.status(400).json({ error: "Поля name и category обязательны" });
  }
  if (!imageUrl) {
    logger.warn("Изображение обязательно для нового продукта");
    return res.status(400).json({ error: "Изображение обязательно для нового продукта" });
  }

  try {
    const [categoryResult] = await db.query("SELECT id FROM categories WHERE name = ?", [category]);
    if (categoryResult.length === 0) {
      logger.warn(`Категория не найдена: ${category}`);
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

    logger.info(`Продукт добавлен: ${name} для филиала ${branchId}`);
    res.status(201).json({ message: "Продукт успешно добавлен", productId });
  } catch (err) {
    logger.error("Ошибка при добавлении продукта:", err.message);
    res.status(500).json({ error: "Ошибка при добавлении продукта" });
  }
});

// Обновление продукта для филиала
app.put("/api/branches/:branchId/products/:id", authenticateAdmin, upload.single("image"), async (req, res) => {
  const branchId = req.params.branchId;
  const productId = req.params.id;
  const { name, description, category, subCategory, price, priceSmall, priceMedium, priceLarge } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : req.body.imageUrl;

  if (!name || !category) {
    logger.warn("Поля name и category обязательны");
    return res.status(400).json({ error: "Поля name и category обязательны" });
  }

  try {
    const [categoryResult] = await db.query("SELECT id FROM categories WHERE name = ?", [category]);
    if (categoryResult.length === 0) {
      logger.warn(`Категория не найдена: ${category}`);
      return res.status(400).json({ error: "Категория не найдена" });
    }
    const categoryId = categoryResult[0].id;

    if (req.file) {
      const [product] = await db.query("SELECT image_url FROM products WHERE id = ?", [productId]);
      if (product.length > 0 && product[0].image_url) {
        const oldImagePath = path.join(__dirname, product[0].image_url);
        try {
          await fs.unlink(oldImagePath);
          logger.info(`Старое изображение удалено: ${oldImagePath}`);
        } catch (err) {
          logger.warn(`Не удалось удалить старое изображение: ${oldImagePath}`, err.message);
        }
      }
    }

    const [productResult] = await db.query(
      `
      UPDATE products 
      SET name = ?, description = ?, category_id = ?, sub_category = ?, image_url = COALESCE(?, image_url)
      WHERE id = ?
      `,
      [name, description || null, categoryId, subCategory || null, imageUrl, productId]
    );
    if (productResult.affectedRows === 0) {
      logger.warn(`Продукт не найден: ${productId}`);
      return res.status(404).json({ error: "Продукт не найден" });
    }

    await db.query(
      `
      UPDATE branch_products 
      SET price_small = ?, price_medium = ?, price_large = ?, price = ?
      WHERE branch_id = ? AND product_id = ?
      `,
      [priceSmall || null, priceMedium || null, priceLarge || null, price || null, branchId, productId]
    );

    logger.info(`Продукт обновлён: ${productId} для филиала ${branchId}`);
    res.status(200).json({ message: "Продукт успешно обновлен" });
  } catch (err) {
    logger.error("Ошибка при обновлении продукта:", err.message);
    res.status(500).json({ error: "Ошибка при обновлении продукта" });
  }
});

// Удаление продукта из филиала
app.delete("/api/branches/:branchId/products/:id", authenticateAdmin, async (req, res) => {
  const branchId = req.params.branchId;
  const productId = req.params.id;

  try {
    await db.query("DELETE FROM branch_products WHERE branch_id = ? AND product_id = ?", [branchId, productId]);

    const [countResult] = await db.query("SELECT COUNT(*) as count FROM branch_products WHERE product_id = ?", [productId]);
    const count = countResult[0].count;

    if (count === 0) {
      const [product] = await db.query("SELECT image_url FROM products WHERE id = ?", [productId]);
      if (product.length > 0 && product[0].image_url) {
        const imagePath = path.join(__dirname, product[0].image_url);
        try {
          await fs.unlink(imagePath);
          logger.info(`Изображение удалено: ${imagePath}`);
        } catch (err) {
          logger.warn(`Не удалось удалить изображение: ${imagePath}`, err.message);
        }
      }
      await db.query("DELETE FROM products WHERE id = ?", [productId]);
      logger.info(`Продукт полностью удалён: ${productId}`);
      res.json({ message: "Продукт успешно удалён" });
    } else {
      logger.info(`Продукт удалён из филиала ${branchId}: ${productId}`);
      res.json({ message: "Продукт удалён из филиала" });
    }
  } catch (err) {
    logger.error("Ошибка при удалении продукта:", err.message);
    res.status(500).json({ error: "Ошибка при удалении продукта" });
  }
});

// Вход администратора
app.post("/api/admin-login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    logger.warn("Не указаны имя пользователя или пароль");
    return res.status(400).json({ message: "Необходимо указать имя пользователя и пароль" });
  }

  try {
    const [results] = await db.query("SELECT * FROM users WHERE username = ?", [username]);
    if (results.length === 0) {
      const hashedPassword = await bcrypt.hash(password, 10);
      const [result] = await db.query(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashedPassword]
      );
      const token = jwt.sign({ userId: result.insertId, username }, JWT_SECRET, {
        expiresIn: "1h",
      });
      logger.info(`Новый администратор создан: ${username}`);
      res.status(201).json({
        message: "Новый администратор создан",
        token,
        userId: result.insertId,
        username,
        generatedPassword: password,
      });
    } else {
      const admin = results[0];
      const validPassword = await bcrypt.compare(password, admin.password);
      if (!validPassword) {
        logger.warn(`Неверный пароль для ${username}`);
        return res.status(401).json({ message: "Неверный пароль" });
      }
      const token = jwt.sign({ userId: admin.id, username }, JWT_SECRET, {
        expiresIn: "1h",
      });
      logger.info(`Администратор вошёл: ${username}`);
      res.json({ message: "Вход выполнен успешно", token, userId: admin.id, username });
    }
  } catch (err) {
    logger.error("Ошибка базы данных при входе:", err.message);
    res.status(500).json({ message: "Ошибка базы данных" });
  }
});

// Отправка заказа в Telegram
app.post("/api/send-order", async (req, res) => {
  try {
    const { orderDetails, deliveryDetails, cartItems, discount, promoCode } = req.body;
    const total = cartItems.reduce(
      (sum, item) => sum + item.originalPrice * item.quantity,
      0
    );
    const discountedTotal = total * (1 - (discount || 0) / 100);

    const orderText = `
📦 *Новый заказ:*
👤 *Имя*: ${orderDetails.name || "Нет"}
📞 *Телефон*: ${orderDetails.phone || "Нет"}
📝 *Комментарии*: ${orderDetails.comments || "Нет"}

🚚 *Доставка:*
👤 *Имя*: ${deliveryDetails.name || "Нет"}
📞 *Телефон*: ${deliveryDetails.phone || "Нет"}
📍 *Адрес*: ${deliveryDetails.address || "Нет"}
📝 *Комментарии*: ${deliveryDetails.comments || "Нет"}

🛒 *Товары:*
${cartItems.map((item) => `- ${item.name} (${item.quantity} шт. по ${item.originalPrice} сом)`).join("\n")}

💰 *Итоговая стоимость товаров*: ${total.toFixed(2)} сом
${promoCode ? `💸 *Скидка (${discount}%):* ${discountedTotal.toFixed(2)} сом` : "💸 Скидка не применена"}
💰 *Итоговая сумма*: ${discountedTotal.toFixed(2)} сом
    `;

    await axios.post(`https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage`, {
      chat_id: TELEGRAM_CHAT_ID,
      text: orderText,
      parse_mode: "Markdown",
    });
    logger.info("Заказ отправлен в Telegram");
    res.status(200).json({ message: "Заказ отправлен в Telegram" });
  } catch (error) {
    logger.error("Ошибка при отправке заказа:", error.message);
    res.status(500).json({ message: "Ошибка отправки заказа", error: error.message });
  }
});

// Регистрация пользователя
app.post("/api/register", async (req, res) => {
  const { firstName, lastName, phone, email, password } = req.body;
  if (!firstName || !lastName || !phone || !email || !password) {
    logger.warn("Не все поля заполнены при регистрации");
    return res.status(400).json({ message: "Заполните все поля" });
  }

  try {
    const [existingUser] = await db.query("SELECT * FROM userskg WHERE email = ? OR phone = ?", [email, phone]);
    if (existingUser.length > 0) {
      logger.warn(`Пользователь уже существует: ${email}`);
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
      html: `
        <div style="text-align: center; font-family: Arial;">
          <h1 style="color: #007BFF;">Подтверждение регистрации</h1>
          <p>Ваш код подтверждения: <b style="color: #FF6347;">${confirmationCode}</b></p>
          <p>Если вы не запрашивали код, проигнорируйте это письмо.</p>
        </div>
      `,
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
  try {
    const [tempUser] = await db.query("SELECT * FROM temp_users WHERE confirmation_code = ?", [code]);
    if (tempUser.length === 0) {
      logger.warn(`Неверный код подтверждения: ${code}`);
      return res.status(400).json({ message: "Неверный код подтверждения" });
    }

    const [result] = await db.query(
      "INSERT INTO userskg (first_name, last_name, phone, email, password_hash) VALUES (?, ?, ?, ?, ?)",
      [tempUser[0].first_name, tempUser[0].last_name, tempUser[0].phone, tempUser[0].email, tempUser[0].password_hash]
    );
    const userId = result.insertId;

    await db.query("DELETE FROM temp_users WHERE confirmation_code = ?", [code]);
    const token = jwt.sign({ user_id: userId }, JWT_SECRET, { expiresIn: "24h" });
    await db.query("UPDATE userskg SET token = ? WHERE user_id = ?", [token, userId]);

    logger.info(`Пользователь подтверждён: ${userId}`);
    res.status(200).json({ message: "Подтверждение успешно", token });
  } catch (error) {
    logger.error("Ошибка при подтверждении кода:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Вход пользователя
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    logger.warn("Не указаны email или пароль");
    return res.status(400).json({ message: "Введите email и пароль" });
  }

  try {
    const [user] = await db.query("SELECT * FROM userskg WHERE email = ?", [email]);
    if (user.length === 0) {
      logger.warn(`Пользователь не найден: ${email}`);
      return res.status(404).json({ message: "Пользователь не найден" });
    }

    const isPasswordMatch = await bcrypt.compare(password, user[0].password_hash);
    if (!isPasswordMatch) {
      logger.warn(`Неверный пароль для ${email}`);
      return res.status(400).json({ message: "Неверный пароль" });
    }

    const token = jwt.sign({ user_id: user[0].user_id }, JWT_SECRET, { expiresIn: "1h" });
    await db.query("UPDATE userskg SET token = ? WHERE user_id = ?", [token, user[0].user_id]);
    logger.info(`Пользователь вошёл: ${email}`);
    res.json({ message: "Вход успешен", token });
  } catch (error) {
    logger.error("Ошибка входа:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Получение информации о пользователе
app.get("/api/user", async (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    logger.warn("Токен отсутствует в запросе");
    return res.status(401).json({ message: "Требуется токен" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const [results] = await db.query(
      "SELECT user_id, first_name AS username, email, phone, balance FROM userskg WHERE user_id = ?",
      [decoded.user_id]
    );
    if (results.length === 0) {
      logger.warn(`Пользователь не найден: ${decoded.user_id}`);
      return res.status(404).json({ message: "Пользователь не найден" });
    }
    res.json(results[0]);
  } catch (error) {
    logger.error("Ошибка запроса:", error.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Получение всех пользователей
app.get("/api/users", authenticateAdmin, async (req, res) => {
  try {
    logger.info("Запрос к /api/users");
    const [results] = await db.query("SELECT * FROM userskg");
    res.json(results);
  } catch (err) {
    logger.error("Ошибка при запросе пользователей:", err.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Удаление пользователя
app.delete("/api/users/:user_id", authenticateAdmin, async (req, res) => {
  const userId = parseInt(req.params.user_id);
  if (isNaN(userId)) {
    logger.warn("Неверный ID пользователя");
    return res.status(400).json({ message: "Неверный ID пользователя" });
  }

  try {
    const [result] = await db.query("DELETE FROM userskg WHERE user_id = ?", [userId]);
    if (result.affectedRows === 0) {
      logger.warn(`Пользователь не найден: ${userId}`);
      return res.status(404).json({ message: "Пользователь не найден" });
    }
    logger.info(`Пользователь удалён: ${userId}`);
    res.json({ message: "Пользователь успешно удален" });
  } catch (err) {
    logger.error("Ошибка при удалении пользователя:", err.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Генерация промокода
function generatePromoCode() {
  return "PROMO-" + Math.random().toString(36).substr(2, 9).toUpperCase();
}

// Отправка промокода
app.post("/api/users/:user_id/promo", authenticateAdmin, async (req, res) => {
  const userId = parseInt(req.params.user_id);
  const { discount } = req.body;

  if (isNaN(userId)) {
    logger.warn("Неверный ID пользователя");
    return res.status(400).json({ message: "Неверный ID пользователя" });
  }
  if (!discount || discount < 1 || discount > 100) {
    logger.warn("Неверная скидка");
    return res.status(400).json({ message: "Скидка должна быть от 1 до 100" });
  }

  try {
    const [user] = await db.query("SELECT email FROM userskg WHERE user_id = ?", [userId]);
    if (user.length === 0) {
      logger.warn(`Пользователь не найден: ${userId}`);
      return res.status(404).json({ message: "Пользователь не найден" });
    }

    const promoCode = generatePromoCode();
    const now = new Date();
    await db.query(
      "UPDATE userskg SET promo_code = ?, promo_code_created_at = ?, discount = ? WHERE user_id = ?",
      [promoCode, now, discount, userId]
    );

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });

    await transporter.sendMail({
      from: `"Boodai Pizza" <${process.env.EMAIL_USER}>`,
      to: user[0].email,
      subject: "Ваш новый промокод от Boodya Pizza",
      html: `
        <div style="background-color: #000; color: #fff; text-align: center; padding: 20px; font-family: Arial;">
          <h1 style="color: #FFD700;">Boodya Pizza</h1>
          <p>Ваш уникальный промокод: <b style="color: #FF6347;">${promoCode}</b></p>
          <p>Скидка: <strong>${discount}%</strong></p>
          <p>Действителен 7 дней.</p>
        </div>
      `,
    });

    logger.info(`Промокод отправлен пользователю ${userId}: ${promoCode}`);
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
    logger.warn("Промокод не указан");
    return res.status(400).json({ message: "Промокод не указан" });
  }

  try {
    const [results] = await db.query("SELECT * FROM userskg WHERE promo_code = ?", [promoCode]);
    if (results.length === 0) {
      logger.warn(`Неверный промокод: ${promoCode}`);
      return res.status(400).json({ message: "Неверный промокод" });
    }

    const { promo_code_created_at, discount } = results[0];
    const createdAt = new Date(promo_code_created_at);
    const expiryDate = new Date(createdAt.getTime() + 7 * 24 * 60 * 60 * 1000);
    if (new Date() > expiryDate) {
      logger.warn(`Промокод истёк: ${promoCode}`);
      return res.status(400).json({ message: "Промокод истёк" });
    }

    res.json({ discount });
  } catch (err) {
    logger.error("Ошибка при проверке промокода:", err.message);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Запуск сервера
const PORT = process.env.PORT || 5000;
app.listen(PORT, "0.0.0.0", () => {
  logger.info(`Сервер запущен на порту ${PORT}`);
});

// Обработка ошибок при запуске
app.on("error", (err) => {
  logger.error("Ошибка при запуске сервера:", err.message);
  process.exit(1);
});
const express = require("express");
const mysql = require("mysql2");
const multer = require("multer");
const path = require("path");
const axios = require("axios");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const crypto = require("crypto");
const cors = require("cors");
require("dotenv").config();
const nodemailer = require("nodemailer");

const app = express();

// Переменные окружения для Telegram и JWT
const TELEGRAM_BOT_TOKEN = process.env.TELEGRAM_BOT;
const TELEGRAM_CHAT_ID = process.env.TELEGRAM_CHAT_ID;
const JWT_SECRET = process.env.JWT_SECRET || "your_default_secret_key";

// CORS настройки
app.use(
  cors({
    origin: "https://boodaikg.com",
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

// Создание папки uploads, если она не существует
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Настройка базы данных с пулом соединений
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

// Проверяем подключение
db.getConnection((err, connection) => {
  if (err) {
    console.error("Ошибка подключения к базе данных:", err.message);
    process.exit(1);
  }
  console.log("Подключено к базе данных MySQL");
  connection.release();

  // Проверка наличия администратора
  const checkAdminQuery = 'SELECT * FROM users WHERE role = "admin"';
  db.query(checkAdminQuery, async (error, results) => {
    if (error) {
      console.error("Ошибка проверки администратора:", error);
      return;
    }
    if (results.length === 0) {
      const generatedUsername = "admin";
      const generatedPassword = crypto.randomBytes(8).toString("hex");
      const hashedPassword = await bcrypt.hash(generatedPassword, 10);
      const generatedToken = crypto.randomBytes(32).toString("hex");

      const insertAdminQuery =
        'INSERT INTO users (username, email, password, role, token, phone, country, gender) VALUES (?, ?, ?, "admin", ?, ?, ?, ?)';
      db.query(
        insertAdminQuery,
        [
          generatedUsername,
          "admin@example.com",
          hashedPassword,
          generatedToken,
          "1234567890",
          "DefaultCountry",
          "male",
        ],
        (error) => {
          if (error) {
            console.error("Ошибка при создании администратора:", error);
          } else {
            console.log(
              `Администратор создан! Логин: ${generatedUsername}, Пароль: ${generatedPassword}`
            );
          }
        }
      );
    } else {
      console.log("Администратор уже существует");
    }
  });
});







// Публичный маршрут для получения всех филиалов
app.get("/api/public/branches", async (req, res) => {
  try {
    const [results] = await db.promise().query("SELECT * FROM branches WHERE status = 'active'");
    res.json(results);
  } catch (err) {
    console.error("Ошибка при получении филиалов (публичный маршрут):", err.message);
    res.status(500).json({ error: "Ошибка при получении филиалов" });
  }
});

// Оставляем существующий маршрут для админки
app.get("/api/branches", authenticateAdmin, async (req, res) => {
  try {
    const [results] = await db.promise().query("SELECT * FROM branches");
    res.json(results);
  } catch (err) {
    console.error("Ошибка при получении филиалов:", err.message);
    res.status(500).json({ error: "Ошибка при получении филиалов" });
  }
});





// Middleware для проверки администратора
const authenticateAdmin = (req, res, next) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Требуется токен" });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Неверный токен" });
    }
    const sql = "SELECT role FROM users WHERE id = ?";
    db.query(sql, [decoded.userId], (error, results) => {
      if (error || results.length === 0 || results[0].role !== "admin") {
        return res.status(403).json({ message: "Доступ запрещён" });
      }
      req.user = decoded;
      next();
    });
  });
};

// Базовый маршрут
app.get("/", (req, res) => {
  res.send("Сервер работает!");
});



// Добавление нового филиала
app.post("/api/branches", authenticateAdmin, async (req, res) => {
  const { name, address, phone, latitude, longitude, status } = req.body;

  if (!name || !address) {
    return res.status(400).json({ error: "Название и адрес обязательны" });
  }

  if (latitude && (latitude < -90 || latitude > 90)) {
    return res.status(400).json({ error: "Широта должна быть в диапазоне от -90 до 90" });
  }
  if (longitude && (longitude < -180 || longitude > 180)) {
    return res.status(400).json({ error: "Долгота должна быть в диапазоне от -180 до 180" });
  }

  const normalizedStatus = status === "active" ? "active" : "inactive";
  try {
    const [result] = await db.promise().query(
      "INSERT INTO branches (name, address, phone, latitude, longitude, status) VALUES (?, ?, ?, ?, ?, ?)",
      [name, address, phone || null, latitude || null, longitude || null, normalizedStatus]
    );
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
    console.error("Ошибка при добавлении филиала:", err.message);
    res.status(500).json({ error: "Ошибка при добавлении филиала" });
  }
});

// Обновление филиала
app.put("/api/branches/:id", authenticateAdmin, async (req, res) => {
  const branchId = req.params.id;
  const { name, address, phone, latitude, longitude, status } = req.body;

  if (!name || !address) {
    return res.status(400).json({ error: "Название и адрес обязательны" });
  }

  if (latitude && (latitude < -90 || latitude > 90)) {
    return res.status(400).json({ error: "Широта должна быть в диапазоне от -90 до 90" });
  }
  if (longitude && (longitude < -180 || longitude > 180)) {
    return res.status(400).json({ error: "Долгота должна быть в диапазоне от -180 до 180" });
  }

  const normalizedStatus = status === "active" ? "active" : "inactive";
  try {
    const [result] = await db.promise().query(
      "UPDATE branches SET name = ?, address = ?, phone = ?, latitude = ?, longitude = ?, status = ? WHERE id = ?",
      [name, address, phone || null, latitude || null, longitude || null, normalizedStatus, branchId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Филиал не найден" });
    }
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
    console.error("Ошибка при обновлении филиала:", err.message);
    res.status(500).json({ error: "Ошибка при обновлении филиала" });
  }
});

// Удаление филиала
app.delete("/api/branches/:id", authenticateAdmin, async (req, res) => {
  const branchId = req.params.id;
  try {
    const [result] = await db.promise().query("DELETE FROM branches WHERE id = ?", [branchId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Филиал не найден" });
    }
    res.json({ message: "Филиал успешно удалён" });
  } catch (err) {
    console.error("Ошибка при удалении филиала:", err.message);
    res.status(500).json({ error: "Ошибка при удалении филиала" });
  }
});

// Получение всех категорий
app.get("/api/categories", authenticateAdmin, async (req, res) => {
  try {
    const [results] = await db.promise().query("SELECT * FROM categories ORDER BY priority ASC");
    res.json(results);
  } catch (err) {
    console.error("Ошибка при получении категорий:", err.message);
    res.status(500).json({ error: "Ошибка при получении категорий" });
  }
});

// Добавление новой категории
app.post("/api/categories", authenticateAdmin, async (req, res) => {
  const { name, emoji, priority } = req.body;

  if (!name) {
    return res.status(400).json({ error: "Название обязательно" });
  }

  try {
    const [result] = await db.promise().query(
      "INSERT INTO categories (name, emoji, priority) VALUES (?, ?, ?)",
      [name, emoji || null, priority || 0]
    );
    res.status(201).json({
      id: result.insertId,
      name,
      emoji,
      priority,
    });
  } catch (err) {
    console.error("Ошибка при добавлении категории:", err.message);
    res.status(500).json({ error: "Ошибка при добавлении категории" });
  }
});

// Обновление категории
app.put("/api/categories/:id", authenticateAdmin, async (req, res) => {
  const categoryId = req.params.id;
  const { name, emoji, priority } = req.body;

  if (!name) {
    return res.status(400).json({ error: "Название обязательно" });
  }

  try {
    const [result] = await db.promise().query(
      "UPDATE categories SET name = ?, emoji = ?, priority = ? WHERE id = ?",
      [name, emoji || null, priority || 0, categoryId]
    );
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Категория не найдена" });
    }
    res.json({
      id: categoryId,
      name,
      emoji,
      priority,
    });
  } catch (err) {
    console.error("Ошибка при обновлении категории:", err.message);
    res.status(500).json({ error: "Ошибка при обновлении категории" });
  }
});

// Удаление категории
app.delete("/api/categories/:id", authenticateAdmin, async (req, res) => {
  const categoryId = req.params.id;
  try {
    const [result] = await db.promise().query("DELETE FROM categories WHERE id = ?", [categoryId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ error: "Категория не найдена" });
    }
    res.json({ message: "Категория успешно удалена" });
  } catch (err) {
    console.error("Ошибка при удалении категории:", err.message);
    res.status(500).json({ error: "Ошибка при удалении категории" });
  }
});
// Публичный маршрут для получения продуктов филиала
app.get("/api/public/branches/:branchId/products", async (req, res) => {
  const branchId = req.params.branchId;
  try {
    const [results] = await db.promise().query(
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
    console.error("Ошибка при запросе данных (публичный маршрут):", err.message);
    res.status(500).json({ error: "Ошибка при получении продуктов" });
  }
});

// Оставляем существующий маршрут для админки
app.get("/api/branches/:branchId/products", authenticateAdmin, async (req, res) => {
  const branchId = req.params.branchId;
  try {
    const [results] = await db.promise().query(
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
    console.error("Ошибка при запросе данных:", err.message);
    res.status(500).json({ error: "Ошибка при получении продуктов" });
  }
});

// Добавление нового продукта для филиала
app.post("/api/branches/:branchId/products", authenticateAdmin, upload.single("image"), async (req, res) => {
  const branchId = req.params.branchId;
  const {
    name,
    description,
    category,
    subCategory,
    price,
    priceSmall,
    priceMedium,
    priceLarge,
  } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : req.body.imageUrl;

  if (!name || !category) {
    return res.status(400).json({ error: "Поля name и category обязательны" });
  }
  if (!imageUrl) {
    return res
      .status(400)
      .json({ error: "Изображение обязательно для нового продукта" });
  }

  try {
    const [categoryResult] = await db.promise().query("SELECT id FROM categories WHERE name = ?", [category]);
    if (categoryResult.length === 0) {
      return res.status(400).json({ error: "Категория не найдена" });
    }
    const categoryId = categoryResult[0].id;

    const [productResult] = await db.promise().query(
      "INSERT INTO products (name, description, category_id, sub_category, image_url) VALUES (?, ?, ?, ?, ?)",
      [name, description || null, categoryId, subCategory || null, imageUrl]
    );
    const productId = productResult.insertId;

    await db.promise().query(
      "INSERT INTO branch_products (branch_id, product_id, price_small, price_medium, price_large, price) VALUES (?, ?, ?, ?, ?, ?)",
      [
        branchId,
        productId,
        priceSmall || null,
        priceMedium || null,
        priceLarge || null,
        price || null,
      ]
    );

    res.status(201).json({ message: "Продукт успешно добавлен", productId });
  } catch (err) {
    console.error("Ошибка при добавлении продукта:", err.message);
    res.status(500).json({ error: "Ошибка при добавлении продукта" });
  }
});

// Обновление продукта для филиала
app.put("/api/branches/:branchId/products/:id", authenticateAdmin, upload.single("image"), async (req, res) => {
  const branchId = req.params.branchId;
  const productId = req.params.id;
  const {
    name,
    description,
    category,
    subCategory,
    price,
    priceSmall,
    priceMedium,
    priceLarge,
  } = req.body;
  const imageUrl = req.file ? `/uploads/${req.file.filename}` : req.body.imageUrl;

  if (!name || !category) {
    return res.status(400).json({ error: "Поля name и category обязательны" });
  }

  try {
    const [categoryResult] = await db.promise().query("SELECT id FROM categories WHERE name = ?", [category]);
    if (categoryResult.length === 0) {
      return res.status(400).json({ error: "Категория не найдена" });
    }
    const categoryId = categoryResult[0].id;

    const [productResult] = await db.promise().query(
      `
      UPDATE products 
      SET name = ?, description = ?, category_id = ?, sub_category = ?, image_url = COALESCE(?, image_url)
      WHERE id = ?
      `,
      [name, description || null, categoryId, subCategory || null, imageUrl, productId]
    );
    if (productResult.affectedRows === 0) {
      return res.status(404).json({ error: "Продукт не найден" });
    }

    await db.promise().query(
      `
      UPDATE branch_products 
      SET price_small = ?, price_medium = ?, price_large = ?, price = ?
      WHERE branch_id = ? AND product_id = ?
      `,
      [priceSmall || null, priceMedium || null, priceLarge || null, price || null, branchId, productId]
    );

    res.status(200).json({ message: "Продукт успешно обновлен" });
  } catch (err) {
    console.error("Ошибка при обновлении продукта:", err.message);
    res.status(500).json({ error: "Ошибка при обновлении продукта" });
  }
});

// Удаление продукта из филиала
app.delete("/api/branches/:branchId/products/:id", authenticateAdmin, async (req, res) => {
  const branchId = req.params.branchId;
  const productId = req.params.id;

  try {
    await db.promise().query("DELETE FROM branch_products WHERE branch_id = ? AND product_id = ?", [branchId, productId]);

    const [countResult] = await db.promise().query("SELECT COUNT(*) as count FROM branch_products WHERE product_id = ?", [productId]);
    const count = countResult[0].count;

    if (count === 0) {
      await db.promise().query("DELETE FROM products WHERE id = ?", [productId]);
      res.json({ message: "Продукт успешно удалён" });
    } else {
      res.json({ message: "Продукт удалён из филиала" });
    }
  } catch (err) {
    console.error("Ошибка при удалении продукта:", err.message);
    res.status(500).json({ error: "Ошибка при удалении продукта" });
  }
});

// Вход администратора
app.post("/api/admin-login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Необходимо указать имя пользователя и пароль" });
  }

  try {
    const [results] = await db.promise().query("SELECT * FROM users WHERE username = ?", [username]);
    if (results.length === 0) {
      const hashedPassword = await bcrypt.hash(password, 10);
      const [result] = await db.promise().query(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [username, hashedPassword]
      );
      const token = jwt.sign({ userId: result.insertId, username }, JWT_SECRET, {
        expiresIn: "1h",
      });
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
        return res.status(401).json({ message: "Неверный пароль" });
      }
      const token = jwt.sign({ userId: admin.id, username }, JWT_SECRET, {
        expiresIn: "1h",
      });
      res.json({ message: "Вход выполнен успешно", token, userId: admin.id, username });
    }
  } catch (err) {
    console.error("Ошибка базы данных:", err);
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
    res.status(200).json({ message: "Заказ отправлен в Telegram" });
  } catch (error) {
    console.error("Ошибка при отправке заказа:", error.message);
    res.status(500).json({ message: "Ошибка отправки заказа", error: error.message });
  }
});

// Регистрация пользователя
app.post("/api/register", async (req, res) => {
  const { firstName, lastName, phone, email, password } = req.body;
  if (!firstName || !lastName || !phone || !email || !password) {
    return res.status(400).json({ message: "Заполните все поля" });
  }

  try {
    const [existingUser] = await db.promise().query("SELECT * FROM userskg WHERE email = ? OR phone = ?", [
      email,
      phone,
    ]);
    if (existingUser.length > 0) {
      return res
        .status(400)
        .json({ message: "Пользователь с таким email или телефоном уже существует" });
    }

    const confirmationCode = Math.floor(100000 + Math.random() * 900000);
    const hashedPassword = await bcrypt.hash(password, 10);

    await db.promise().query(
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

    res.status(201).json({ message: "Код подтверждения отправлен на почту" });
  } catch (error) {
    console.error("Ошибка при регистрации:", error);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Подтверждение кода
app.post("/api/confirm-code", async (req, res) => {
  const { code } = req.body;
  try {
    const [tempUser] = await db.promise().query("SELECT * FROM temp_users WHERE confirmation_code = ?", [
      code,
    ]);
    if (tempUser.length === 0) {
      return res.status(400).json({ message: "Неверный код подтверждения" });
    }

    const [result] = await db.promise().query(
      "INSERT INTO userskg (first_name, last_name, phone, email, password_hash) VALUES (?, ?, ?, ?, ?)",
      [tempUser[0].first_name, tempUser[0].last_name, tempUser[0].phone, tempUser[0].email, tempUser[0].password_hash]
    );
    const userId = result.insertId;

    await db.promise().query("DELETE FROM temp_users WHERE confirmation_code = ?", [code]);
    const token = jwt.sign({ user_id: userId }, JWT_SECRET, { expiresIn: "24h" });
    await db.promise().query("UPDATE userskg SET token = ? WHERE user_id = ?", [token, userId]);

    res.status(200).json({ message: "Подтверждение успешно", token });
  } catch (error) {
    console.error("Ошибка при подтверждении кода:", error);
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
    const [user] = await db.promise().query("SELECT * FROM userskg WHERE email = ?", [email]);
    if (user.length === 0) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }

    const isPasswordMatch = await bcrypt.compare(password, user[0].password_hash);
    if (!isPasswordMatch) {
      return res.status(400).json({ message: "Неверный пароль" });
    }

    const token = jwt.sign({ user_id: user[0].user_id }, JWT_SECRET, { expiresIn: "1h" });
    await db.promise().query("UPDATE userskg SET token = ? WHERE user_id = ?", [token, user[0].user_id]);
    res.json({ message: "Вход успешен", token });
  } catch (error) {
    console.error("Ошибка входа:", error);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Получение информации о пользователе
app.get("/api/user", async (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Требуется токен" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const [results] = await db.promise().query(
      "SELECT user_id, first_name AS username, email, phone, balance FROM userskg WHERE user_id = ?",
      [decoded.user_id]
    );
    if (results.length === 0) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }
    res.json(results[0]);
  } catch (error) {
    console.error("Ошибка запроса:", error);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Получение всех пользователей
app.get("/api/users", authenticateAdmin, async (req, res) => {
  try {
    const [results] = await db.promise().query("SELECT * FROM userskg");
    res.json(results);
  } catch (err) {
    console.error("Ошибка при запросе пользователей:", err);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Удаление пользователя
app.delete("/api/users/:user_id", authenticateAdmin, async (req, res) => {
  const userId = parseInt(req.params.user_id);
  if (isNaN(userId)) {
    return res.status(400).json({ message: "Неверный ID пользователя" });
  }

  try {
    const [result] = await db.promise().query("DELETE FROM userskg WHERE user_id = ?", [userId]);
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }
    res.json({ message: "Пользователь успешно удален" });
  } catch (err) {
    console.error("Ошибка при удалении пользователя:", err);
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
    return res.status(400).json({ message: "Неверный ID пользователя" });
  }
  if (!discount || discount < 1 || discount > 100) {
    return res.status(400).json({ message: "Скидка должна быть от 1 до 100" });
  }

  try {
    const [user] = await db.promise().query("SELECT email FROM userskg WHERE user_id = ?", [userId]);
    if (user.length === 0) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }

    const promoCode = generatePromoCode();
    const now = new Date();
    await db.promise().query(
      "UPDATE userskg SET promo_code = ?, promo_code_created_at = ?, discount = ? WHERE user_id = ?",
      [promoCode, now, discount, userId]
    );

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: "vorlodgamess@gmail.com", pass: "hpmjnrjmaedrylve" },
    });

    await transporter.sendMail({
      from: "vorlodgamess@gmail.com",
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

    res.json({ promoCode, discount });
  } catch (error) {
    console.error("Ошибка при отправке промокода:", error);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Проверка промокода
app.post("/api/validate-promo", async (req, res) => {
  const { promoCode } = req.body;
  if (!promoCode) {
    return res.status(400).json({ message: "Промокод не указан" });
  }

  try {
    const [results] = await db.promise().query("SELECT * FROM userskg WHERE promo_code = ?", [promoCode]);
    if (results.length === 0) {
      return res.status(400).json({ message: "Неверный промокод" });
    }

    const { promo_code_created_at, discount } = results[0];
    const createdAt = new Date(promo_code_created_at);
    const expiryDate = new Date(createdAt.getTime() + 7 * 24 * 60 * 60 * 1000);
    if (new Date() > expiryDate) {
      return res.status(400).json({ message: "Промокод истек" });
    }

    res.json({ discount });
  } catch (err) {
    console.error("Ошибка при проверке промокода:", err);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Запуск сервера
app.listen(5000, () => {
  console.log("Сервер запущен на порту 5000");
});
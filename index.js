const express = require("express");
const mysql = require("mysql");
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
const SFTPClient = require("ssh2-sftp-client");

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

// Настройка базы данных
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Подключение к базе данных
db.connect((err) => {
  if (err) {
    console.error("Ошибка подключения к базе данных:", err.message);
    process.exit(1); // Завершаем процесс, если база недоступна
  }
  console.log("Подключено к базе данных MySQL");

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

// Базовый маршрут
app.get("/", (req, res) => {
  res.send("Сервер работает!");
});

// Получение всех продуктов
app.get("/api/products", (req, res) => {
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
      console.error("Ошибка при запросе данных:", err.message);
      return res.status(500).json({ error: "Ошибка при получении продуктов" });
    }
    res.json(results);
  });
});
// Добавление/обновление продукта (оставляем POST для создания нового продукта)
app.post("/api/products", upload.single("image"), (req, res) => {
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

  // Добавление нового продукта
  const productSql =
    "INSERT INTO products (name, description, category, sub_category, image_url) VALUES (?, ?, ?, ?, ?)";
  db.query(
    productSql,
    [name, description || null, category, subCategory || null, imageUrl],
    (err, result) => {
      if (err) {
        console.error("Ошибка при добавлении продукта:", err);
        return res.status(500).json({ error: "Ошибка при добавлении продукта" });
      }
      const productId = result.insertId;
      const priceSql =
        "INSERT INTO prices (product_id, price_small, price, price_medium, price_large) VALUES (?, ?, ?, ?, ?)";
      db.query(
        priceSql,
        [productId, priceSmall || null, price || null, priceMedium || null, priceLarge || null],
        (err) => {
          if (err) {
            console.error("Ошибка при добавлении цен:", err);
            return res.status(500).json({ error: "Ошибка при добавлении цен" });
          }
          res.status(201).json({ message: "Продукт успешно добавлен", productId });
        }
      );
    }
  );
});

// Обновление продукта (новый маршрут PUT)
app.put("/api/products/:id", upload.single("image"), (req, res) => {
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

  // Обновление данных продукта
  const updateProductQuery = `
    UPDATE products 
    SET name = ?, description = ?, category = ?, sub_category = ?, image_url = COALESCE(?, image_url)
    WHERE id = ?
  `;
  db.query(
    updateProductQuery,
    [name, description || null, category, subCategory || null, imageUrl, productId],
    (err, result) => {
      if (err) {
        console.error("Ошибка при обновлении продукта:", err);
        return res.status(500).json({ error: "Ошибка при обновлении продукта" });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({ error: "Продукт не найден" });
      }

      // Обновление цен (если они переданы)
      if (price || priceSmall || priceMedium || priceLarge) {
        const updatePriceQuery = `
          UPDATE prices 
          SET price_small = ?, price_medium = ?, price_large = ?, price = ?
          WHERE product_id = ?
        `;
        db.query(
          updatePriceQuery,
          [
            priceSmall || null,
            priceMedium || null,
            priceLarge || null,
            price || null,
            productId,
          ],
          (err) => {
            if (err) {
              console.error("Ошибка при обновлении цен:", err);
              return res.status(500).json({ error: "Ошибка при обновлении цен" });
            }
            res.status(200).json({ message: "Продукт успешно обновлен" });
          }
        );
      } else {
        res.status(200).json({ message: "Продукт успешно обновлен" });
      }
    }
  );
});
// Удаление продукта
app.delete("/api/products/:id", (req, res) => {
  const productId = req.params.id;
  const sql = "DELETE FROM products WHERE id = ?";
  db.query(sql, [productId], (err) => {
    if (err) {
      console.error("Ошибка при удалении продукта:", err);
      return res.status(500).json({ error: "Ошибка базы данных" });
    }
    res.json({ message: "Продукт успешно удален" });
  });
});

// Вход администратора
app.post("/api/admin-login", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res
      .status(400)
      .json({ message: "Необходимо указать имя пользователя и пароль" });
  }

  const sql = "SELECT * FROM users WHERE username = ?";
  db.query(sql, [username], async (err, results) => {
    if (err) {
      console.error("Ошибка базы данных:", err);
      return res.status(500).json({ message: "Ошибка базы данных" });
    }
    if (results.length === 0) {
      const hashedPassword = await bcrypt.hash(password, 10);
      const insertSql = "INSERT INTO users (username, password) VALUES (?, ?)";
      db.query(insertSql, [username, hashedPassword], (err, result) => {
        if (err) {
          console.error("Ошибка создания администратора:", err);
          return res
            .status(500)
            .json({ message: "Ошибка создания администратора" });
        }
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
  });
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
    const [existingUser] = await query("SELECT * FROM userskg WHERE email = ? OR phone = ?", [
      email,
      phone,
    ]);
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "Пользователь с таким email или телефоном уже существует" });
    }

    const confirmationCode = Math.floor(100000 + Math.random() * 900000);
    const hashedPassword = await bcrypt.hash(password, 10);

    await query(
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
    const [tempUser] = await query("SELECT * FROM temp_users WHERE confirmation_code = ?", [
      code,
    ]);
    if (!tempUser) {
      return res.status(400).json({ message: "Неверный код подтверждения" });
    }

    const userId = await query(
      "INSERT INTO userskg (first_name, last_name, phone, email, password_hash) VALUES (?, ?, ?, ?, ?)",
      [tempUser.first_name, tempUser.last_name, tempUser.phone, tempUser.email, tempUser.password_hash]
    ).then((result) => result.insertId);

    await query("DELETE FROM temp_users WHERE confirmation_code = ?", [code]);
    const token = jwt.sign({ user_id: userId }, JWT_SECRET, { expiresIn: "24h" });
    await query("UPDATE userskg SET token = ? WHERE user_id = ?", [token, userId]);

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
    const [user] = await query("SELECT * FROM userskg WHERE email = ?", [email]);
    if (!user) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }

    const isPasswordMatch = await bcrypt.compare(password, user.password_hash);
    if (!isPasswordMatch) {
      return res.status(400).json({ message: "Неверный пароль" });
    }

    const token = jwt.sign({ user_id: user.user_id }, JWT_SECRET, { expiresIn: "1h" });
    await query("UPDATE userskg SET token = ? WHERE user_id = ?", [token, user.user_id]);
    res.json({ message: "Вход успешен", token });
  } catch (error) {
    console.error("Ошибка при входе:", error);
    res.status(500).json({ message: "Ошибка сервера" });
  }
});

// Получение информации о пользователе
app.get("/api/user", (req, res) => {
  const token = req.headers["authorization"]?.split(" ")[1];
  if (!token) {
    return res.status(401).json({ message: "Требуется токен" });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Неверный токен" });
    }
    const sql = "SELECT user_id, first_name AS username, email, phone, balance FROM userskg WHERE user_id = ?";
    db.query(sql, [decoded.user_id], (error, results) => {
      if (error) {
        console.error("Ошибка запроса:", error);
        return res.status(500).json({ message: "Ошибка сервера" });
      }
      if (results.length === 0) {
        return res.status(404).json({ message: "Пользователь не найден" });
      }
      res.json(results[0]);
    });
  });
});

// Получение всех пользователей
app.get("/api/users", (req, res) => {
  const query = "SELECT * FROM userskg";
  db.query(query, (err, results) => {
    if (err) {
      console.error("Ошибка при запросе пользователей:", err);
      return res.status(500).json({ message: "Ошибка сервера" });
    }
    res.json(results);
  });
});

// Удаление пользователя
app.delete("/api/users/:user_id", (req, res) => {
  const userId = parseInt(req.params.user_id);
  if (isNaN(userId)) {
    return res.status(400).json({ message: "Неверный ID пользователя" });
  }

  const sql = "DELETE FROM userskg WHERE user_id = ?";
  db.query(sql, [userId], (err, result) => {
    if (err) {
      console.error("Ошибка при удалении пользователя:", err);
      return res.status(500).json({ message: "Ошибка сервера" });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }
    res.json({ message: "Пользователь успешно удален" });
  });
});

// Генерация промокода
function generatePromoCode() {
  return "PROMO-" + Math.random().toString(36).substr(2, 9).toUpperCase();
}

// Отправка промокода
app.post("/api/users/:user_id/promo", async (req, res) => {
  const userId = parseInt(req.params.user_id);
  const { discount } = req.body;

  if (isNaN(userId)) {
    return res.status(400).json({ message: "Неверный ID пользователя" });
  }
  if (!discount || discount < 1 || discount > 100) {
    return res.status(400).json({ message: "Скидка должна быть от 1 до 100" });
  }

  try {
    const [user] = await query("SELECT email FROM userskg WHERE user_id = ?", [userId]);
    if (!user) {
      return res.status(404).json({ message: "Пользователь не найден" });
    }

    const promoCode = generatePromoCode();
    const now = new Date();
    await query(
      "UPDATE userskg SET promo_code = ?, promo_code_created_at = ?, discount = ? WHERE user_id = ?",
      [promoCode, now, discount, userId]
    );

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: "vorlodgamess@gmail.com", pass: "hpmjnrjmaedrylve" },
    });

    await transporter.sendMail({
      from: "vorlodgamess@gmail.com",
      to: user.email,
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
app.post("/api/validate-promo", (req, res) => {
  const { promoCode } = req.body;
  if (!promoCode) {
    return res.status(400).json({ message: "Промокод не указан" });
  }

  const query = "SELECT * FROM userskg WHERE promo_code = ?";
  db.query(query, [promoCode], (err, results) => {
    if (err) {
      console.error("Ошибка при проверке промокода:", err);
      return res.status(500).json({ message: "Ошибка сервера" });
    }
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
  });
});

// Вспомогательная функция для асинхронных запросов
function query(sql, params) {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, result) => {
      if (err) reject(err);
      else resolve(result);
    });
  });
}

// Запуск сервера
app.listen(5000, () => {
  console.log("Сервер запущен на порту 5000");
});
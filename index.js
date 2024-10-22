const express = require("express");
const path = require("path");
const jwt = require("jsonwebtoken");
const { open } = require("sqlite");
const sqlite3 = require("sqlite3");
const bcrypt = require("bcryptjs");
const app = express();
const cors = require("cors");

app.use(cors({ origin: "http://localhost:3001" }));
app.use(express.json());
require("dotenv").config();

// SQLite database file path
const dbPath = path.join(__dirname, "expenses.db");
let db = null;

const initializeDBAndServer = async () => {
  try {
    db = await open({
      filename: dbPath,
      driver: sqlite3.Database,
    });
    app.listen(process.env.PORT, () => {
      console.log(`Server running at http://localhost:${process.env.PORT}/`);
    });
  } catch (e) {
    console.log(`DB Error: ${e.message}`);
    process.exit(1);
  }
};

initializeDBAndServer();

// User Registration
app.post("/register", async (request, response) => {
  const { username, email, password } = request.body;

  // Validate the request body
  if (!username || !email || !password) {
    return response
      .status(400)
      .send("Username, email, and password are required");
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const selectUserQuery = `SELECT * FROM users WHERE username = ? OR email = ?`;

  try {
    const dbUser = await db.get(selectUserQuery, [username, email]);
    if (dbUser === undefined) {
      const createUserQuery = `
                INSERT INTO 
                  users (username, email, password) 
                VALUES 
                  (?, ?, ?)`;
      const dbResponse = await db.run(createUserQuery, [
        username,
        email,
        hashedPassword,
      ]);
      const newUserId = dbResponse.lastID;
      response.status(201).send(`Created new user with id ${newUserId}`);
    } else {
      response.status(400).send("User already exists");
    }
  } catch (error) {
    console.error("Database error:", error.message);
    response.status(500).send("Internal server error");
  }
});

// User Login
app.post("/login", async (request, response) => {
  const { username, password } = request.body;

  // Validate the request body
  if (!username || !password) {
    return response.status(400).send("Username and password are required");
  }

  const selectUserQuery = `SELECT * FROM users WHERE username = ?`;

  try {
    const dbUser = await db.get(selectUserQuery, [username]);
    if (dbUser === undefined) {
      return response.status(400).send("Invalid User");
    }

    const isPasswordMatched = await bcrypt.compare(password, dbUser.password);
    if (isPasswordMatched) {
      const payload = { user_id: dbUser.id, username };
      const jwtToken = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: "7d",
      });
      response.send({ jwtToken });
    } else {
      response.status(400).send("Invalid Password");
    }
  } catch (error) {
    console.error("Database error:", error.message);
    response.status(500).send("Internal server error");
  }
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  let token = null;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    token = authHeader.split(" ")[1];
  } else {
    return res.sendStatus(401);
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Transaction API Endpoints

app.post("/transactions", authenticateToken, async (req, res) => {
  const { type, category, amount, date, description } = req.body;
  const { user_id } = req.user;
  const postTransactionQuery = `
    INSERT INTO transactions (user_id, type, category, amount, date, description)
    VALUES ('${user_id}', '${type}', '${category}', '${amount}', '${date}', '${description}')`;
  await db.run(postTransactionQuery);
  res.send("Transaction added successfully");
});

app.get("/transactions", authenticateToken, async (req, res) => {
  const { user_id } = req.user;
  const { page = 1, limit = 10 } = req.query; // Default to page 1 and limit 10

  const offset = (page - 1) * limit; // Calculate the offset for pagination
  const getTransactionsQuery = `SELECT * FROM transactions WHERE user_id = ${user_id} LIMIT ${limit} OFFSET ${offset}`;
  const transactions = await db.all(getTransactionsQuery);

  // Get the total count of transactions for the user
  const totalTransactionsQuery = `SELECT COUNT(*) AS total FROM transactions WHERE user_id = ${user_id}`;
  const totalCount = await db.get(totalTransactionsQuery);

  res.send({
    transactions,
    total: totalCount.total,
    page: parseInt(page, 10),
    limit: parseInt(limit, 10),
  });
});

app.get("/transactions/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { user_id } = req.user;
  const getTransactionQuery = `SELECT * FROM transactions WHERE id = ${id} AND user_id = ${user_id}`;
  const transaction = await db.get(getTransactionQuery);
  if (transaction) {
    res.send(transaction);
  } else {
    res.status(404).send("Transaction not found");
  }
});

app.put("/transactions/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { type, category, amount, date, description } = req.body;
  const { user_id } = req.user;
  const updateTransactionQuery = `
    UPDATE transactions
    SET type='${type}', category='${category}', amount='${amount}', date='${date}', description='${description}'
    WHERE id = ${id} AND user_id = ${user_id}`;
  await db.run(updateTransactionQuery);
  res.send("Transaction updated successfully");
});

app.delete("/transactions/:id", authenticateToken, async (req, res) => {
  const { id } = req.params;
  const { user_id } = req.user;
  const deleteTransactionQuery = `DELETE FROM transactions WHERE id = ${id} AND user_id = ${user_id}`;
  await db.run(deleteTransactionQuery);
  res.send("Transaction deleted successfully");
});

// Summary Endpoint
app.get("/summary", authenticateToken, async (req, res) => {
  const { user_id } = req.user;
  const { category, startDate, endDate } = req.query;
  let summaryQuery = `SELECT type, SUM(amount) as totalAmount FROM transactions WHERE user_id = ${user_id}`;

  if (category) {
    summaryQuery += ` AND category = '${category}'`;
  }

  if (startDate && endDate) {
    summaryQuery += ` AND date BETWEEN '${startDate}' AND '${endDate}'`;
  }

  summaryQuery += ` GROUP BY type`;
  const summary = await db.all(summaryQuery);
  res.send(summary);
});

app.get("/reports/monthly-spending", authenticateToken, async (req, res) => {
  const { user_id } = req.user;
  const reportQuery = `
      SELECT 
        categories.name AS category, 
        strftime('%Y-%m', transactions.date) AS month, 
        SUM(transactions.amount) AS total_spending
      FROM 
        transactions
      JOIN 
        categories ON transactions.category = categories.id
      WHERE 
        transactions.user_id = ${user_id}
      GROUP BY 
        category, month
      ORDER BY 
        month DESC
    `;

  const reportData = await db.all(reportQuery);
  res.send(reportData);
});

module.exports = app;

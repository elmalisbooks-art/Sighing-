
const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");

const app = express();

const PORT = process.env.PORT || 3000;
const DATABASE_URL = process.env.DATABASE_URL;
const JWT_SECRET = process.env.JWT_SECRET;
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;

// Validate important environment variables
if (!DATABASE_URL) {
  throw new Error("DATABASE_URL environment variable is required.");
}

if (
  process.env.NODE_ENV === "production" &&
  (!JWT_SECRET || JWT_SECRET.length < 32)
) {
  throw new Error(
    "JWT_SECRET must be at least 32 characters."
  );
}

// PostgreSQL database connection
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl:
    process.env.DATABASE_SSL === "true"
      ? { rejectUnauthorized: false }
      : undefined,
});

// Security and middleware
app.use(helmet());
app.use(express.json({ limit: "10kb" }));

app.use(
  cors({
    origin: FRONTEND_ORIGIN || true,
  })
);

app.use(
  "/api",
  rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 100,
    standardHeaders: "draft-7",
    legacyHeaders: false,
  })
);

// Create the members table automatically
async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS members (
      id SERIAL PRIMARY KEY,
      real_name VARCHAR(100) NOT NULL,
      phone VARCHAR(10) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `);

  console.log("Database table is ready.");
}

// Validate registration details
function validateMember(realName, phone, password) {
  if (
    typeof realName !== "string" ||
    !/^[\p{L}]+(?:[ '\u2019-][\p{L}]+)*$/u.test(realName.trim())
  ) {
    return "Enter a valid real name using letters and spaces.";
  }

  if (
    typeof phone !== "string" ||
    !/^(07|01)\d{8}$/.test(phone)
  ) {
    return "Phone number must contain 10 digits and start with 07 or 01.";
  }

  if (
    typeof password !== "string" ||
    password.length < 4 ||
    password.length > 10
  ) {
    return "Password must be between 4 and 10 characters.";
  }

  return null;
}

// Home route
app.get("/", (req, res) => {
  res.send("Member Portal Backend is running.");
});

// Health check route
app.get("/api/health", async (req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({
      status: "ok",
      database: "connected",
    });
  } catch (error) {
    console.error("Health check failed:", error.message);
    res.status(500).json({
      status: "error",
      database: "unavailable",
    });
  }
});

// Register a new member
app.post("/api/signup", async (req, res) => {
  try {
    const { realName, phone, password } = req.body || {};

    const validationError = validateMember(
      realName,
      phone,
      password
    );

    if (validationError) {
      return res.status(400).json({
        error: validationError,
      });
    }

    const cleanName = realName.trim().replace(/\s+/g, " ");

    const existingMember = await pool.query(
      "SELECT id FROM members WHERE phone = $1",
      [phone]
    );

    if (existingMember.rows.length > 0) {
      return res.status(409).json({
        error: "This phone number is already registered.",
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO members
        (real_name, phone, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, real_name, phone, created_at`,
      [cleanName, phone, passwordHash]
    );

    return res.status(201).json({
      message: "Registration successful.",
      member: result.rows[0],
    });
  } catch (error) {
    console.error("Signup error:", error.message);

    if (error.code === "23505") {
      return res.status(409).json({
        error: "This phone number is already registered.",
      });
    }

    return res.status(500).json({
      error: "Registration failed. Please try again.",
    });
  }
});

// Login using phone number AND password
app.post("/api/login", async (req, res) => {
  try {
    const { phone, password } = req.body || {};

    if (
      typeof phone !== "string" ||
      !/^(07|01)\d{8}$/.test(phone) ||
      typeof password !== "string" ||
      password.length < 4 ||
      password.length > 10
    ) {
      return res.status(400).json({
        error: "Enter a valid phone number and password.",
      });
    }

    const result = await pool.query(
      `SELECT id, real_name, phone, password_hash, created_at
       FROM members
       WHERE phone = $1`,
      [phone]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({
        error: "Incorrect phone number or password.",
      });
    }

    const member = result.rows[0];

    const passwordMatches = await bcrypt.compare(
      password,
      member.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        error: "Incorrect phone number or password.",
      });
    }

    return res.json({
      message: "Login successful.",
      member: {
        id: member.id,
        real_name: member.real_name,
        phone: member.phone,
        created_at: member.created_at,
      },
    });
  } catch (error) {
    console.error("Login error:", error.message);

    return res.status(500).json({
      error: "Login failed. Please try again.",
    });
  }
});

// Start server after connecting to the database
async function startServer() {
  try {
    await initializeDatabase();

    app.listen(PORT, "0.0.0.0", () => {
      console.log(`Server running on port ${PORT}`);
    });
  } catch (error) {
    console.error("Failed to start backend:", error.message);
    process.exit(1);
  }
}

startServer();
                                                

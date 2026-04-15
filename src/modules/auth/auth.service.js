import crypto from "crypto";
import pg from "pg";
import ApiError from "../../common/utils/api-error.js";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  generateResetToken,
} from "../../common/utils/jwt.utils.js";

// same DB config as index.mjs
const pool = new pg.Pool({
  host: "localhost",
  port: 5433,
  user: "postgres",
  password: "postgres",
  database: "sql_class_2_db",
});

const hashToken = (token) =>
  crypto.createHash("sha256").update(token).digest("hex");


// 🔐 REGISTER
const register = async ({ name, email, password, role }) => {
  const existing = await pool.query(
    "SELECT * FROM users WHERE email = $1",
    [email]
  );

  if (existing.rows.length > 0) {
    throw ApiError.conflict("Email already registered");
  }

  const { rawToken, hashedToken } = generateResetToken();

  const result = await pool.query(
    `INSERT INTO users 
    (id, first_name, email, password, role, verification_token)
    VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)
    RETURNING *`,
    [name, email, password, role || "customer", hashedToken]
  );

  const user = result.rows[0];

  delete user.password;
  delete user.verification_token;

  console.log("Verification token:", rawToken); // simulate email

  return user;
};


// 🔐 LOGIN
const login = async ({ email, password }) => {
  const result = await pool.query(
    "SELECT * FROM users WHERE email = $1",
    [email]
  );

  const user = result.rows[0];

  if (!user) throw ApiError.unauthorized("Invalid email or password");

  // ⚠️ plain compare for now (later hash)
  if (user.password !== password) {
    throw ApiError.unauthorized("Invalid email or password");
  }

  // if (!user.is_verified) {
  //   throw ApiError.forbidden("Please verify your email");
  // }

  const accessToken = generateAccessToken({ id: user.id, role: user.role });
  const refreshToken = generateRefreshToken({ id: user.id });

  await pool.query(
    "UPDATE users SET refresh_token = $1 WHERE id = $2",
    [hashToken(refreshToken), user.id]
  );

  delete user.password;
  delete user.refresh_token;

  return { user, accessToken, refreshToken };
};


// 🔄 REFRESH TOKEN
const refresh = async (token) => {
  if (!token) throw ApiError.unauthorized("Refresh token missing");

  const decoded = verifyRefreshToken(token);

  const result = await pool.query(
    "SELECT * FROM users WHERE id = $1",
    [decoded.id]
  );

  const user = result.rows[0];

  if (!user) throw ApiError.unauthorized("User not found");

  if (user.refresh_token !== hashToken(token)) {
    throw ApiError.unauthorized("Invalid refresh token");
  }

  const accessToken = generateAccessToken({ id: user.id, role: user.role });

  return { accessToken };
};


// 🚪 LOGOUT
const logout = async (userId) => {
  await pool.query(
    "UPDATE users SET refresh_token = NULL WHERE id = $1",
    [userId]
  );
};


// 📩 VERIFY EMAIL
const verifyEmail = async (token) => {
  const hashed = hashToken(token);

  const result = await pool.query(
    "SELECT * FROM users WHERE verification_token = $1",
    [hashed]
  );

  const user = result.rows[0];

  if (!user) throw ApiError.badRequest("Invalid token");

  await pool.query(
    `UPDATE users 
     SET is_verified = true, verification_token = NULL 
     WHERE id = $1`,
    [user.id]
  );

  return user;
};


// 🔁 FORGOT PASSWORD
const forgotPassword = async (email) => {
  const result = await pool.query(
    "SELECT * FROM users WHERE email = $1",
    [email]
  );

  const user = result.rows[0];

  if (!user) throw ApiError.notFound("No account");

  const { rawToken, hashedToken } = generateResetToken();

  await pool.query(
    `UPDATE users 
     SET reset_password_token = $1,
         reset_password_expires = $2
     WHERE id = $3`,
    [hashedToken, Date.now() + 15 * 60 * 1000, user.id]
  );

  console.log("Reset token:", rawToken);
};


// 🔁 RESET PASSWORD
const resetPassword = async (token, newPassword) => {
  const hashed = hashToken(token);

  const result = await pool.query(
    `SELECT * FROM users 
     WHERE reset_password_token = $1 
     AND reset_password_expires > $2`,
    [hashed, Date.now()]
  );

  const user = result.rows[0];

  if (!user) throw ApiError.badRequest("Invalid token");

  await pool.query(
    `UPDATE users 
     SET password = $1,
         reset_password_token = NULL,
         reset_password_expires = NULL
     WHERE id = $2`,
    [newPassword, user.id]
  );
};


// 👤 GET ME
const getMe = async (userId) => {
  const result = await pool.query(
    "SELECT * FROM users WHERE id = $1",
    [userId]
  );

  const user = result.rows[0];

  if (!user) throw ApiError.notFound("User not found");

  delete user.password;
  return user;
};

export {
  register,
  login,
  refresh,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
  getMe,
};
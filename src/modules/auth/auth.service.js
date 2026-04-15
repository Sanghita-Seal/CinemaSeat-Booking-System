import crypto from "crypto";
import ApiError from "../../common/utils/api-error.js";
import {
  generateAccessToken,
  generateRefreshToken,
  verifyRefreshToken,
  generateResetToken,
} from "../../common/utils/jwt.utils.js";

import pool from "../../common/config/db.js";

const hashToken = (token) =>
  crypto.createHash("sha256").update(token).digest("hex");


const register = async ({ name, email, password, role }) => {
  const existing = await pool.query(
    "SELECT * FROM users WHERE email = $1",
    [email]
  );

  if (existing.rows.length > 0) {
    throw ApiError.conflict("Email already registered");
  }

  const result = await pool.query(
    `INSERT INTO users 
    (id, first_name, email, password, role)
    VALUES (gen_random_uuid(), $1, $2, $3, $4)
    RETURNING *`,
    [name, email, password, role || "customer"]
  );

  const user = result.rows[0];

  delete user.password;

  return user;
};



const login = async ({ email, password }) => {
  const result = await pool.query(
    "SELECT * FROM users WHERE email = $1",
    [email]
  );

  const user = result.rows[0];

  if (!user) throw ApiError.unauthorized("Invalid email or password");

  if (user.password !== password) {
    throw ApiError.unauthorized("Invalid email or password");
  }

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


const logout = async (userId) => {
  await pool.query(
    "UPDATE users SET refresh_token = NULL WHERE id = $1",
    [userId]
  );
};


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
  forgotPassword,
  resetPassword,
  getMe,
};
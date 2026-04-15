import ApiError from "../../common/utils/api-error.js";
import { verifyAccessToken } from "../../common/utils/jwt.utils.js";
import pg from "pg";
import  pool from "../../common/config/db.js";




const authenticate = async (req, res, next) => {
  try {
    let token;
    

    if (req.headers.authorization?.startsWith("Bearer ")) {
      token = req.headers.authorization.split(" ")[1];
    }
    console.log("AUTH HEADER:", req.headers.authorization);
console.log("TOKEN:", token);
    if (!token) throw ApiError.unauthorized("Not authenticated");

    const decoded = verifyAccessToken(token);

    const result = await pool.query(
      "SELECT * FROM users WHERE id = $1",
      [decoded.id]
    );

    const user = result.rows[0];

    if (!user) throw ApiError.unauthorized("User no longer exists");

    req.user = {
      id: user.id,
      role: user.role,
      name: user.first_name,
      email: user.email,
    };

    next();
  } catch (err) {
    next(err); // IMP. passes to global error handler
  }
};

const authorize = (...roles) => {
    
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        ApiError.forbidden(
          "You do not have permission to perform this action"
        )
      );
    }
    next();
  };
};

export { authenticate, authorize };
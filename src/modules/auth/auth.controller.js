import * as authService from "./auth.service.js";
import ApiResponse from "../../common/utils/api-response.js";
import ApiError from "../../common/utils/api-error.js";

const register = async (req, res) => {
  try {
    const user = await authService.register(req.body);
    return ApiResponse.created(
      res,
      "Registration successful. Please verify your email.",
      user
    );
  } catch (err) {
    throw err instanceof ApiError
      ? err
      : ApiError.internal(err.message);
  }
};

const login = async (req, res) => {
  try {
    const { user, accessToken, refreshToken } = await authService.login(req.body);

    res.cookie("refreshToken", refreshToken, {
      httpOnly: true,
      secure: false, // keep false for local
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });

    return ApiResponse.ok(res, "Login successful", {
      user,
      accessToken,
    });
  } catch (err) {
    throw err instanceof ApiError
      ? err
      : ApiError.internal(err.message);
  }
};

const refreshToken = async (req, res) => {
  try {
    const token = req.cookies?.refreshToken;
    const { accessToken } = await authService.refresh(token);

    return ApiResponse.ok(res, "Token refreshed", { accessToken });
  } catch (err) {
    throw err instanceof ApiError
      ? err
      : ApiError.internal(err.message);
  }
};

const logout = async (req, res) => {
  try {
    await authService.logout(req.user.id);
    res.clearCookie("refreshToken");

    return ApiResponse.ok(res, "Logged out successfully");
  } catch (err) {
    throw err instanceof ApiError
      ? err
      : ApiError.internal(err.message);
  }
};

const verifyEmail = async (req, res) => {
  try {
    await authService.verifyEmail(req.params.token);

    return ApiResponse.ok(res, "Email verified successfully");
  } catch (err) {
    throw err instanceof ApiError
      ? err
      : ApiError.internal(err.message);
  }
};

const forgotPassword = async (req, res) => {
  try {
    await authService.forgotPassword(req.body.email);

    return ApiResponse.ok(res, "Password reset email sent");
  } catch (err) {
    throw err instanceof ApiError
      ? err
      : ApiError.internal(err.message);
  }
};

const resetPassword = async (req, res) => {
  try {
    await authService.resetPassword(req.params.token, req.body.password);

    return ApiResponse.ok(res, "Password reset successful");
  } catch (err) {
    throw err instanceof ApiError
      ? err
      : ApiError.internal(err.message);
  }
};

const getMe = async (req, res) => {
  try {
    const user = await authService.getMe(req.user.id);

    return ApiResponse.ok(res, "User profile", user);
  } catch (err) {
    throw err instanceof ApiError
      ? err
      : ApiError.internal(err.message);
  }
};

export {
  register,
  login,
  refreshToken,
  logout,
  verifyEmail,
  forgotPassword,
  resetPassword,
  getMe,
};
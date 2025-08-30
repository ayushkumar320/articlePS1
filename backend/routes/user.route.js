import express from "express";
import {authenticateUser} from "../middlewares/middleware.js";
import {
  registerUser,
  loginUser,
  getUserDashboard,
  getAllArticles,
  getArticleById,
  createArticle,
  getUserArticles,
  updateArticle,
  deleteArticle,
} from "../controllers/user.controller.js";

const router = express.Router();

// User Authentication Routes
router.post("/register", registerUser);
router.post("/login", loginUser);

// User Dashboard
router.get("/dashboard", authenticateUser, getUserDashboard);

// Public Article Routes
router.get("/articles", getAllArticles);
router.get("/articles/:id", getArticleById);

// User Article Routes (Protected)
router.post("/articles", authenticateUser, createArticle);
router.get("/my-articles", authenticateUser, getUserArticles);
router.put("/articles/:id", authenticateUser, updateArticle);
router.delete("/articles/:id", authenticateUser, deleteArticle);

export default router;

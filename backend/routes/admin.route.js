import express from "express";
import { authenticateAdmin } from "../middlewares/middleware.js";
import {
  registerAdmin,
  loginAdmin,
  getAdminDashboard,
  getPendingArticles,
  getAllArticlesAdmin,
  getArticleByIdAdmin,
  approveArticle,
  rejectArticle,
  unpublishArticle,
  deleteArticleAdmin,
  getAllUsers,
  getUserArticles,
  getAnalytics,
} from "../controllers/admin.controller.js";

const router = express.Router();

// Admin Authentication Routes
router.post("/register", registerAdmin);
router.post("/login", loginAdmin);

// Admin Dashboard
router.get("/dashboard", authenticateAdmin, getAdminDashboard);

// Article Management Routes
router.get("/articles/pending", authenticateAdmin, getPendingArticles);
router.get("/articles", authenticateAdmin, getAllArticlesAdmin);
router.get("/articles/:id", authenticateAdmin, getArticleByIdAdmin);
router.put("/articles/:id/approve", authenticateAdmin, approveArticle);
router.put("/articles/:id/reject", authenticateAdmin, rejectArticle);
router.put("/articles/:id/unpublish", authenticateAdmin, unpublishArticle);
router.delete("/articles/:id", authenticateAdmin, deleteArticleAdmin);

// User Management Routes
router.get("/users", authenticateAdmin, getAllUsers);
router.get("/users/:id/articles", authenticateAdmin, getUserArticles);

// Analytics Routes
router.get("/analytics", authenticateAdmin, getAnalytics);

export default router;

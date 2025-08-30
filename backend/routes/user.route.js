import express from "express";
import {authenticateUser, generateToken} from "../middlewares/middleware.js";
import User from "../models/user.models.js";
import Article from "../models/article.models.js";

const router = express.Router();

// User Authentication Routes
// POST /api/users/register
router.post("/register", async (req, res) => {
  try {
    const {username, email, password} = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{email}, {username}],
    });

    if (existingUser) {
      return res.status(409).json({
        success: false,
        message: "User with this email or username already exists",
      });
    }

    // Create user (store password as plain text since you're using JWT)
    const user = new User({
      username,
      email,
      password, // Store password as is (you mentioned no bcrypt)
    });

    await user.save();

    // Generate token
    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error during registration",
      error: error.message,
    });
  }
});

// POST /api/users/login
router.post("/login", async (req, res) => {
  try {
    const {email, password} = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    // Find user
    const user = await User.findOne({email});
    if (!user) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Verify password (simple comparison since no bcrypt)
    if (password !== user.password) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Generate token
    const token = generateToken(user._id);

    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error during login",
      error: error.message,
    });
  }
});

// Protected User Routes (require authentication)

// GET /api/users/dashboard - User dashboard
router.get("/dashboard", authenticateUser, async (req, res) => {
  try {
    // Get user's articles count
    const totalArticles = await Article.countDocuments({author: req.user._id});
    const publishedArticles = await Article.countDocuments({
      author: req.user._id,
      status: "published",
    });
    const pendingArticles = await Article.countDocuments({
      author: req.user._id,
      status: "pending",
    });

    // Get recent articles
    const recentArticles = await Article.find({author: req.user._id})
      .sort({createdAt: -1})
      .limit(5)
      .select("title status createdAt");

    res.json({
      success: true,
      dashboard: {
        user: {
          username: req.user.username,
          email: req.user.email,
        },
        stats: {
          totalArticles,
          publishedArticles,
          pendingArticles,
        },
        recentArticles,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching dashboard data",
      error: error.message,
    });
  }
});

// GET /api/users/articles - View all published articles (public access for users)
router.get("/articles", async (req, res) => {
  try {
    const {page = 1, limit = 10, category, search} = req.query;

    let query = {status: "published"};

    // Add category filter if provided
    if (category) {
      query.categoryTags = {$in: [category.toLowerCase()]};
    }

    // Add search filter if provided
    if (search) {
      query.$or = [
        {title: {$regex: search, $options: "i"}},
        {shortDescription: {$regex: search, $options: "i"}},
      ];
    }

    const articles = await Article.find(query)
      .populate("author", "username")
      .sort({publishedDate: -1})
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select(
        "coverImage title shortDescription categoryTags publishedDate author"
      );

    const totalArticles = await Article.countDocuments(query);

    res.json({
      success: true,
      articles,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalArticles / limit),
        totalArticles,
        hasNext: page < Math.ceil(totalArticles / limit),
        hasPrev: page > 1,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching articles",
      error: error.message,
    });
  }
});

// GET /api/users/articles/:id - View single article
router.get("/articles/:id", async (req, res) => {
  try {
    const article = await Article.findOne({
      _id: req.params.id,
      status: "published",
    }).populate("author", "username email");

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    res.json({
      success: true,
      article,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching article",
      error: error.message,
    });
  }
});

// POST /api/users/articles - Create new article (requires authentication)
router.post("/articles", authenticateUser, async (req, res) => {
  try {
    const {coverImage, title, shortDescription, fullDescription, categoryTags} =
      req.body;

    // Validation
    if (!coverImage || !title || !shortDescription || !fullDescription) {
      return res.status(400).json({
        success: false,
        message: "All required fields must be provided",
      });
    }

    // Create article with pending status (needs admin approval)
    const article = new Article({
      coverImage,
      title,
      shortDescription,
      fullDescription,
      categoryTags: categoryTags || [],
      author: req.user._id,
      status: "pending", // Articles start as pending
    });

    await article.save();

    res.status(201).json({
      success: true,
      message: "Article created successfully and sent for approval",
      article: {
        id: article._id,
        title: article.title,
        status: article.status,
        createdAt: article.createdAt,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error creating article",
      error: error.message,
    });
  }
});

// GET /api/users/my-articles - Get user's own articles
router.get("/my-articles", authenticateUser, async (req, res) => {
  try {
    const {page = 1, limit = 10, status} = req.query;

    let query = {author: req.user._id};

    if (status && ["pending", "published", "rejected"].includes(status)) {
      query.status = status;
    }

    const articles = await Article.find(query)
      .sort({createdAt: -1})
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select("coverImage title shortDescription status createdAt updatedAt");

    const totalArticles = await Article.countDocuments(query);

    res.json({
      success: true,
      articles,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalArticles / limit),
        totalArticles,
        hasNext: page < Math.ceil(totalArticles / limit),
        hasPrev: page > 1,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching your articles",
      error: error.message,
    });
  }
});

// PUT /api/users/articles/:id - Update article (only if pending or rejected)
router.put("/articles/:id", authenticateUser, async (req, res) => {
  try {
    const article = await Article.findOne({
      _id: req.params.id,
      author: req.user._id,
    });

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    // Only allow updates if article is pending or rejected
    if (article.status === "published") {
      return res.status(403).json({
        success: false,
        message: "Cannot modify published articles",
      });
    }

    const {coverImage, title, shortDescription, fullDescription, categoryTags} =
      req.body;

    // Update fields
    if (coverImage) article.coverImage = coverImage;
    if (title) article.title = title;
    if (shortDescription) article.shortDescription = shortDescription;
    if (fullDescription) article.fullDescription = fullDescription;
    if (categoryTags) article.categoryTags = categoryTags;

    // Reset status to pending if it was rejected
    if (article.status === "rejected") {
      article.status = "pending";
    }

    await article.save();

    res.json({
      success: true,
      message: "Article updated successfully",
      article,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error updating article",
      error: error.message,
    });
  }
});

// DELETE /api/users/articles/:id - Delete article (only if not published)
router.delete("/articles/:id", authenticateUser, async (req, res) => {
  try {
    const article = await Article.findOne({
      _id: req.params.id,
      author: req.user._id,
    });

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    // Don't allow deletion of published articles
    if (article.status === "published") {
      return res.status(403).json({
        success: false,
        message: "Cannot delete published articles",
      });
    }

    await Article.findByIdAndDelete(req.params.id);

    res.json({
      success: true,
      message: "Article deleted successfully",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error deleting article",
      error: error.message,
    });
  }
});

export default router;

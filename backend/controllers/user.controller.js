import jwt from "jsonwebtoken";
import {generateToken} from "../middlewares/middleware.js";
import User from "../models/user.models.js";
import Article from "../models/article.models.js";

// User Authentication Controllers
export const registerUser = async (req, res) => {
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
};

export const loginUser = async (req, res) => {
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
};

export const getUserDashboard = async (req, res) => {
  try {
    // Get user's article statistics
    const totalArticles = await Article.countDocuments({author: req.user._id});
    const publishedArticles = await Article.countDocuments({
      author: req.user._id,
      status: "published",
    });
    const pendingArticles = await Article.countDocuments({
      author: req.user._id,
      status: "pending",
    });
    const rejectedArticles = await Article.countDocuments({
      author: req.user._id,
      status: "rejected",
    });

    // Get recent articles
    const recentArticles = await Article.find({author: req.user._id})
      .sort({createdAt: -1})
      .limit(5)
      .select("title status createdAt");

    res.json({
      success: true,
      data: {
        user: {
          id: req.user._id,
          username: req.user.username,
          email: req.user.email,
        },
        stats: {
          totalArticles,
          publishedArticles,
          pendingArticles,
          rejectedArticles,
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
};

// Article Controllers
export const getAllArticles = async (req, res) => {
  try {
    const {page = 1, limit = 10, category, search} = req.query;

    // Build query - only show published articles to public
    let query = {status: "published"};

    if (category) {
      query.categoryTags = {$in: [category.toLowerCase()]};
    }

    if (search) {
      query.$or = [
        {title: {$regex: search, $options: "i"}},
        {shortDescription: {$regex: search, $options: "i"}},
        {categoryTags: {$in: [new RegExp(search, "i")]}},
      ];
    }

    const articles = await Article.find(query)
      .populate("author", "username")
      .sort({publishedDate: -1})
      .limit(limit * 1)
      .skip((page - 1) * limit)
      .select("-fullDescription"); // Don't send full description in list

    const total = await Article.countDocuments(query);

    res.json({
      success: true,
      data: {
        articles,
        totalPages: Math.ceil(total / limit),
        currentPage: page,
        total,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching articles",
      error: error.message,
    });
  }
};

export const getArticleById = async (req, res) => {
  try {
    const {id} = req.params;

    const article = await Article.findOne({
      _id: id,
      status: "published", // Only show published articles to public
    }).populate("author", "username email");

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found or not published",
      });
    }

    res.json({
      success: true,
      data: {article},
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching article",
      error: error.message,
    });
  }
};

export const createArticle = async (req, res) => {
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
};

export const getUserArticles = async (req, res) => {
  try {
    const {page = 1, limit = 10, status} = req.query;

    let query = {author: req.user._id};

    if (status && ["pending", "published", "rejected"].includes(status)) {
      query.status = status;
    }

    const articles = await Article.find(query)
      .sort({createdAt: -1})
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Article.countDocuments(query);

    res.json({
      success: true,
      data: {
        articles,
        totalPages: Math.ceil(total / limit),
        currentPage: page,
        total,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching your articles",
      error: error.message,
    });
  }
};

export const updateArticle = async (req, res) => {
  try {
    const {id} = req.params;
    const {coverImage, title, shortDescription, fullDescription, categoryTags} =
      req.body;

    // Find article and verify ownership
    const article = await Article.findOne({_id: id, author: req.user._id});

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found or you don't have permission to edit it",
      });
    }

    // Don't allow editing published articles
    if (article.status === "published") {
      return res.status(403).json({
        success: false,
        message: "Published articles cannot be edited",
      });
    }

    // Update fields
    if (coverImage) article.coverImage = coverImage;
    if (title) article.title = title;
    if (shortDescription) article.shortDescription = shortDescription;
    if (fullDescription) article.fullDescription = fullDescription;
    if (categoryTags) article.categoryTags = categoryTags;

    // Reset to pending if it was rejected and now being updated
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
};

export const deleteArticle = async (req, res) => {
  try {
    const {id} = req.params;

    // Find and delete article (only if user owns it)
    const article = await Article.findOneAndDelete({
      _id: id,
      author: req.user._id,
    });

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found or you don't have permission to delete it",
      });
    }

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
};

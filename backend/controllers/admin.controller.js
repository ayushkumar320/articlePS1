import bcrypt from "bcrypt";
import {generateToken} from "../middlewares/middleware.js";
import Admin from "../models/admin.models.js";
import Article from "../models/article.models.js";
import User from "../models/user.models.js";

// Admin Authentication Controllers
export const registerAdmin = async (req, res) => {
  try {
    const {username, email, password} = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: "All fields are required",
      });
    }

    // Check if admin already exists
    const existingAdmin = await Admin.findOne({
      $or: [{email}, {username}],
    });

    if (existingAdmin) {
      return res.status(409).json({
        success: false,
        message: "Admin with this email or username already exists",
      });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create admin
    const admin = new Admin({
      username,
      email,
      password: hashedPassword,
    });

    await admin.save();

    // Generate token
    const token = generateToken(admin._id);

    res.status(201).json({
      success: true,
      message: "Admin registered successfully",
      token,
      admin: {
        id: admin._id,
        username: admin.username,
        email: admin.email,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error during admin registration",
      error: error.message,
    });
  }
};

export const loginAdmin = async (req, res) => {
  try {
    const {email, password} = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: "Email and password are required",
      });
    }

    // Find admin
    const admin = await Admin.findOne({email});
    if (!admin) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, admin.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // Generate token
    const token = generateToken(admin._id);

    res.json({
      success: true,
      message: "Admin login successful",
      token,
      admin: {
        id: admin._id,
        username: admin.username,
        email: admin.email,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Server error during admin login",
      error: error.message,
    });
  }
};

export const getAdminDashboard = async (req, res) => {
  try {
    // Get statistics
    const totalArticles = await Article.countDocuments();
    const pendingArticles = await Article.countDocuments({status: "pending"});
    const publishedArticles = await Article.countDocuments({
      status: "published",
    });
    const rejectedArticles = await Article.countDocuments({status: "rejected"});
    const totalUsers = await User.countDocuments();

    // Get recent articles
    const recentArticles = await Article.find()
      .populate("author", "username")
      .sort({createdAt: -1})
      .limit(10)
      .select("title status createdAt author");

    // Get recent users
    const recentUsers = await User.find()
      .sort({createdAt: -1})
      .limit(5)
      .select("username email createdAt");

    res.json({
      success: true,
      data: {
        admin: {
          id: req.user._id,
          username: req.user.username,
          email: req.user.email,
        },
        stats: {
          totalArticles,
          pendingArticles,
          publishedArticles,
          rejectedArticles,
          totalUsers,
        },
        recentArticles,
        recentUsers,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching admin dashboard data",
      error: error.message,
    });
  }
};

// Article Management Controllers
export const getPendingArticles = async (req, res) => {
  try {
    const {page = 1, limit = 10} = req.query;

    const articles = await Article.find({status: "pending"})
      .populate("author", "username email")
      .sort({createdAt: -1})
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await Article.countDocuments({status: "pending"});

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
      message: "Error fetching pending articles",
      error: error.message,
    });
  }
};

export const getAllArticlesAdmin = async (req, res) => {
  try {
    const {page = 1, limit = 10, status, search} = req.query;

    // Build query
    let query = {};

    if (status && ["pending", "published", "rejected"].includes(status)) {
      query.status = status;
    }

    if (search) {
      query.$or = [
        {title: {$regex: search, $options: "i"}},
        {shortDescription: {$regex: search, $options: "i"}},
        {categoryTags: {$in: [new RegExp(search, "i")]}},
      ];
    }

    const articles = await Article.find(query)
      .populate("author", "username email")
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
      message: "Error fetching articles",
      error: error.message,
    });
  }
};

export const getArticleByIdAdmin = async (req, res) => {
  try {
    const {id} = req.params;

    const article = await Article.findById(id).populate(
      "author",
      "username email"
    );

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
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

export const approveArticle = async (req, res) => {
  try {
    const {id} = req.params;

    const article = await Article.findById(id);

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    if (article.status !== "pending") {
      return res.status(400).json({
        success: false,
        message: "Only pending articles can be approved",
      });
    }

    article.status = "published";
    article.publishedDate = new Date();
    await article.save();

    // Populate author info for response
    await article.populate("author", "username email");

    res.json({
      success: true,
      message: "Article approved and published successfully",
      article,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error approving article",
      error: error.message,
    });
  }
};

export const rejectArticle = async (req, res) => {
  try {
    const {id} = req.params;
    const {reason} = req.body;

    const article = await Article.findById(id);

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    if (article.status !== "pending") {
      return res.status(400).json({
        success: false,
        message: "Only pending articles can be rejected",
      });
    }

    article.status = "rejected";
    if (reason) {
      article.rejectionReason = reason;
    }
    await article.save();

    // Populate author info for response
    await article.populate("author", "username email");

    res.json({
      success: true,
      message: "Article rejected successfully",
      article,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error rejecting article",
      error: error.message,
    });
  }
};

export const unpublishArticle = async (req, res) => {
  try {
    const {id} = req.params;
    const {reason} = req.body;

    const article = await Article.findById(id);

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
      });
    }

    if (article.status !== "published") {
      return res.status(400).json({
        success: false,
        message: "Only published articles can be unpublished",
      });
    }

    article.status = "rejected";
    if (reason) {
      article.rejectionReason = reason;
    }
    await article.save();

    // Populate author info for response
    await article.populate("author", "username email");

    res.json({
      success: true,
      message: "Article unpublished successfully",
      article,
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error unpublishing article",
      error: error.message,
    });
  }
};

export const deleteArticleAdmin = async (req, res) => {
  try {
    const {id} = req.params;

    const article = await Article.findByIdAndDelete(id);

    if (!article) {
      return res.status(404).json({
        success: false,
        message: "Article not found",
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

// User Management Controllers
export const getAllUsers = async (req, res) => {
  try {
    const {page = 1, limit = 10, search} = req.query;

    let query = {};

    if (search) {
      query.$or = [
        {username: {$regex: search, $options: "i"}},
        {email: {$regex: search, $options: "i"}},
      ];
    }

    const users = await User.find(query)
      .select("-password")
      .sort({createdAt: -1})
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const total = await User.countDocuments(query);

    // Get article counts for each user
    const usersWithStats = await Promise.all(
      users.map(async (user) => {
        const articleCount = await Article.countDocuments({author: user._id});
        const publishedCount = await Article.countDocuments({
          author: user._id,
          status: "published",
        });
        return {
          ...user.toObject(),
          articleCount,
          publishedCount,
        };
      })
    );

    res.json({
      success: true,
      data: {
        users: usersWithStats,
        totalPages: Math.ceil(total / limit),
        currentPage: page,
        total,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching users",
      error: error.message,
    });
  }
};

export const getUserArticles = async (req, res) => {
  try {
    const {id} = req.params;
    const {page = 1, limit = 10, status} = req.query;

    // Verify user exists
    const user = await User.findById(id).select("-password");
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    let query = {author: id};

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
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
        },
        articles,
        totalPages: Math.ceil(total / limit),
        currentPage: page,
        total,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching user articles",
      error: error.message,
    });
  }
};

// Analytics Controller
export const getAnalytics = async (req, res) => {
  try {
    const {period = "month"} = req.query;

    // Calculate date range
    let startDate;
    const endDate = new Date();

    switch (period) {
      case "week":
        startDate = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        break;
      case "month":
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
        break;
      case "year":
        startDate = new Date(Date.now() - 365 * 24 * 60 * 60 * 1000);
        break;
      default:
        startDate = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    }

    // Get articles created in period
    const articlesInPeriod = await Article.countDocuments({
      createdAt: {$gte: startDate, $lte: endDate},
    });

    const publishedInPeriod = await Article.countDocuments({
      createdAt: {$gte: startDate, $lte: endDate},
      status: "published",
    });

    const usersInPeriod = await User.countDocuments({
      createdAt: {$gte: startDate, $lte: endDate},
    });

    // Get most active authors
    const topAuthors = await Article.aggregate([
      {$match: {status: "published"}},
      {$group: {_id: "$author", count: {$sum: 1}}},
      {$sort: {count: -1}},
      {$limit: 5},
      {
        $lookup: {
          from: "users",
          localField: "_id",
          foreignField: "_id",
          as: "author",
        },
      },
      {$unwind: "$author"},
      {
        $project: {
          _id: 1,
          count: 1,
          username: "$author.username",
          email: "$author.email",
        },
      },
    ]);

    // Get popular categories
    const popularCategories = await Article.aggregate([
      {$match: {status: "published"}},
      {$unwind: "$categoryTags"},
      {$group: {_id: "$categoryTags", count: {$sum: 1}}},
      {$sort: {count: -1}},
      {$limit: 10},
    ]);

    res.json({
      success: true,
      data: {
        period,
        startDate,
        endDate,
        stats: {
          articlesInPeriod,
          publishedInPeriod,
          usersInPeriod,
        },
        topAuthors,
        popularCategories,
      },
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: "Error fetching analytics",
      error: error.message,
    });
  }
};

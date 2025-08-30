import express from 'express';
import bcrypt from 'bcrypt';
import { authenticateAdmin } from '../middlewares/middleware.js'; 
import { generateToken } from '../middlewares/middleware.js';
import Admin from '../models/admin.models.js';
import Article from '../models/article.models.js';
import User from '../models/user.models.js';

const router = express.Router();

// Admin Authentication Routes
// POST /api/admin/register
router.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validation
    if (!username || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'All fields are required'
      });
    }

    // Check if admin already exists
    const existingAdmin = await Admin.findOne({
      $or: [{ email }, { username }]
    });

    if (existingAdmin) {
      return res.status(409).json({
        success: false,
        message: 'Admin with this email or username already exists'
      });
    }

    // Hash password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Create admin
    const admin = new Admin({
      username,
      email,
      password: hashedPassword
    });

    await admin.save();

    // Generate token
    const token = generateToken(admin._id);

    res.status(201).json({
      success: true,
      message: 'Admin registered successfully',
      token,
      admin: {
        id: admin._id,
        username: admin.username,
        email: admin.email
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error during registration',
      error: error.message
    });
  }
});

// POST /api/admin/login
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Email and password are required'
      });
    }

    // Find admin
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Verify password
    const isValidPassword = await bcrypt.compare(password, admin.password);
    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'Invalid credentials'
      });
    }

    // Generate token
    const token = generateToken(admin._id);

    res.json({
      success: true,
      message: 'Admin login successful',
      token,
      admin: {
        id: admin._id,
        username: admin.username,
        email: admin.email
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Server error during login',
      error: error.message
    });
  }
});

// Protected Admin Routes (require admin authentication)

// GET /api/admin/dashboard - Admin dashboard
router.get('/dashboard', authenticateAdmin, async (req, res) => {
  try {
    // Get statistics
    const totalArticles = await Article.countDocuments();
    const publishedArticles = await Article.countDocuments({ status: 'published' });
    const pendingArticles = await Article.countDocuments({ status: 'pending' });
    const rejectedArticles = await Article.countDocuments({ status: 'rejected' });
    const totalUsers = await User.countDocuments();
    const totalAdmins = await Admin.countDocuments();

    // Get recent articles needing approval
    const recentPendingArticles = await Article.find({ status: 'pending' })
      .populate('author', 'username email')
      .sort({ createdAt: -1 })
      .limit(5)
      .select('title shortDescription author createdAt');

    res.json({
      success: true,
      dashboard: {
        admin: {
          username: req.user.username,
          email: req.user.email
        },
        stats: {
          totalArticles,
          publishedArticles,
          pendingArticles,
          rejectedArticles,
          totalUsers,
          totalAdmins
        },
        recentPendingArticles
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching dashboard data',
      error: error.message
    });
  }
});

// GET /api/admin/articles/pending - Get all pending articles
router.get('/articles/pending', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10 } = req.query;

    const articles = await Article.find({ status: 'pending' })
      .populate('author', 'username email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const totalPendingArticles = await Article.countDocuments({ status: 'pending' });

    res.json({
      success: true,
      articles,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalPendingArticles / limit),
        totalArticles: totalPendingArticles,
        hasNext: page < Math.ceil(totalPendingArticles / limit),
        hasPrev: page > 1
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching pending articles',
      error: error.message
    });
  }
});

// GET /api/admin/articles - Get all articles with status filter
router.get('/articles', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status, author, search } = req.query;
    
    let query = {};
    
    // Add status filter
    if (status && ['pending', 'published', 'rejected'].includes(status)) {
      query.status = status;
    }
    
    // Add author filter
    if (author) {
      query.author = author;
    }
    
    // Add search filter
    if (search) {
      query.$or = [
        { title: { $regex: search, $options: 'i' } },
        { shortDescription: { $regex: search, $options: 'i' } }
      ];
    }

    const articles = await Article.find(query)
      .populate('author', 'username email')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const totalArticles = await Article.countDocuments(query);

    res.json({
      success: true,
      articles,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalArticles / limit),
        totalArticles,
        hasNext: page < Math.ceil(totalArticles / limit),
        hasPrev: page > 1
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching articles',
      error: error.message
    });
  }
});

// GET /api/admin/articles/:id - Get single article for review
router.get('/articles/:id', authenticateAdmin, async (req, res) => {
  try {
    const article = await Article.findById(req.params.id)
      .populate('author', 'username email');

    if (!article) {
      return res.status(404).json({
        success: false,
        message: 'Article not found'
      });
    }

    res.json({
      success: true,
      article
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching article',
      error: error.message
    });
  }
});

// PUT /api/admin/articles/:id/approve - Approve an article
router.put('/articles/:id/approve', authenticateAdmin, async (req, res) => {
  try {
    const article = await Article.findById(req.params.id);

    if (!article) {
      return res.status(404).json({
        success: false,
        message: 'Article not found'
      });
    }

    if (article.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Only pending articles can be approved'
      });
    }

    // Update article status to published
    article.status = 'published';
    article.publishedDate = new Date();
    await article.save();

    // Populate author for response
    await article.populate('author', 'username email');

    res.json({
      success: true,
      message: 'Article approved and published successfully',
      article
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error approving article',
      error: error.message
    });
  }
});

// PUT /api/admin/articles/:id/reject - Reject an article
router.put('/articles/:id/reject', authenticateAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    
    const article = await Article.findById(req.params.id);

    if (!article) {
      return res.status(404).json({
        success: false,
        message: 'Article not found'
      });
    }

    if (article.status !== 'pending') {
      return res.status(400).json({
        success: false,
        message: 'Only pending articles can be rejected'
      });
    }

    // Update article status to rejected
    article.status = 'rejected';
    if (reason) {
      article.rejectionReason = reason;
    }
    await article.save();

    // Populate author for response
    await article.populate('author', 'username email');

    res.json({
      success: true,
      message: 'Article rejected successfully',
      article
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error rejecting article',
      error: error.message
    });
  }
});

// PUT /api/admin/articles/:id/unpublish - Unpublish a published article
router.put('/articles/:id/unpublish', authenticateAdmin, async (req, res) => {
  try {
    const { reason } = req.body;
    
    const article = await Article.findById(req.params.id);

    if (!article) {
      return res.status(404).json({
        success: false,
        message: 'Article not found'
      });
    }

    if (article.status !== 'published') {
      return res.status(400).json({
        success: false,
        message: 'Only published articles can be unpublished'
      });
    }

    // Update article status
    article.status = 'rejected';
    if (reason) {
      article.rejectionReason = reason;
    }
    await article.save();

    res.json({
      success: true,
      message: 'Article unpublished successfully',
      article
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error unpublishing article',
      error: error.message
    });
  }
});

// DELETE /api/admin/articles/:id - Delete any article
router.delete('/articles/:id', authenticateAdmin, async (req, res) => {
  try {
    const article = await Article.findById(req.params.id);

    if (!article) {
      return res.status(404).json({
        success: false,
        message: 'Article not found'
      });
    }

    await Article.findByIdAndDelete(req.params.id);

    res.json({
      success: true,
      message: 'Article deleted successfully'
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error deleting article',
      error: error.message
    });
  }
});

// GET /api/admin/users - Get all users
router.get('/users', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, search } = req.query;
    
    let query = {};
    
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } }
      ];
    }

    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const totalUsers = await User.countDocuments(query);

    // Get article count for each user
    const usersWithStats = await Promise.all(
      users.map(async (user) => {
        const articleCount = await Article.countDocuments({ author: user._id });
        const publishedCount = await Article.countDocuments({ 
          author: user._id, 
          status: 'published' 
        });
        
        return {
          ...user.toObject(),
          stats: {
            totalArticles: articleCount,
            publishedArticles: publishedCount
          }
        };
      })
    );

    res.json({
      success: true,
      users: usersWithStats,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalUsers / limit),
        totalUsers,
        hasNext: page < Math.ceil(totalUsers / limit),
        hasPrev: page > 1
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching users',
      error: error.message
    });
  }
});

// GET /api/admin/users/:id/articles - Get articles by specific user
router.get('/users/:id/articles', authenticateAdmin, async (req, res) => {
  try {
    const { page = 1, limit = 10, status } = req.query;
    
    // Check if user exists
    const user = await User.findById(req.params.id).select('-password');
    if (!user) {
      return res.status(404).json({
        success: false,
        message: 'User not found'
      });
    }

    let query = { author: req.params.id };
    if (status && ['pending', 'published', 'rejected'].includes(status)) {
      query.status = status;
    }

    const articles = await Article.find(query)
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    const totalArticles = await Article.countDocuments(query);

    res.json({
      success: true,
      user,
      articles,
      pagination: {
        currentPage: parseInt(page),
        totalPages: Math.ceil(totalArticles / limit),
        totalArticles,
        hasNext: page < Math.ceil(totalArticles / limit),
        hasPrev: page > 1
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching user articles',
      error: error.message
    });
  }
});

// GET /api/admin/analytics - Get platform analytics
router.get('/analytics', authenticateAdmin, async (req, res) => {
  try {
    // Get counts by status
    const articleStats = await Article.aggregate([
      {
        $group: {
          _id: '$status',
          count: { $sum: 1 }
        }
      }
    ]);

    // Get articles by month (last 6 months)
    const sixMonthsAgo = new Date();
    sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const monthlyStats = await Article.aggregate([
      {
        $match: {
          createdAt: { $gte: sixMonthsAgo }
        }
      },
      {
        $group: {
          _id: {
            year: { $year: '$createdAt' },
            month: { $month: '$createdAt' }
          },
          count: { $sum: 1 }
        }
      },
      {
        $sort: { '_id.year': 1, '_id.month': 1 }
      }
    ]);

    // Get top authors
    const topAuthors = await Article.aggregate([
      {
        $match: { status: 'published' }
      },
      {
        $group: {
          _id: '$author',
          publishedCount: { $sum: 1 }
        }
      },
      {
        $sort: { publishedCount: -1 }
      },
      {
        $limit: 10
      },
      {
        $lookup: {
          from: 'users',
          localField: '_id',
          foreignField: '_id',
          as: 'author'
        }
      },
      {
        $unwind: '$author'
      },
      {
        $project: {
          'author.username': 1,
          'author.email': 1,
          publishedCount: 1
        }
      }
    ]);

    // Get popular categories
    const popularCategories = await Article.aggregate([
      {
        $match: { status: 'published' }
      },
      {
        $unwind: '$categoryTags'
      },
      {
        $group: {
          _id: '$categoryTags',
          count: { $sum: 1 }
        }
      },
      {
        $sort: { count: -1 }
      },
      {
        $limit: 10
      }
    ]);

    res.json({
      success: true,
      analytics: {
        articleStats,
        monthlyStats,
        topAuthors,
        popularCategories
      }
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: 'Error fetching analytics',
      error: error.message
    });
  }
});

export default router;
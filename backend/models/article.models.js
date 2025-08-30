import mongoose from "mongoose";

const articleSchema = new mongoose.Schema(
  {
    coverImage: {
      type: String,
      required: true,
      trim: true,
    },
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 200,
    },
    shortDescription: {
      type: String,
      required: true,
      trim: true,
      maxlength: 500,
    },
    fullDescription: {
      type: String,
      required: true,
      trim: true,
    },
    categoryTags: [
      {
        type: String,
        trim: true,
        lowercase: true,
      },
    ],
    publishedDate: {
      type: Date,
      default: Date.now,
    },
    author: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

const Article = mongoose.model("Article", articleSchema);

export default Article;

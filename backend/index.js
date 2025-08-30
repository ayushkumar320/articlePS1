import connectDB from "./db/dbConnection.js";
import express from "express";
import cros from "cors";
import adminRouter from "./routes/admin.route.js";
import userRouter from "./routes/user.route.js";
import dotenv from "dotenv";
dotenv.config();

connectDB();

const app = express();
app.use(cros());
app.use(express.json());

app.use("/api/admin", adminRouter);
app.use("/api/users", userRouter);

app.listen(process.env.PORT, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});

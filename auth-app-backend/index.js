const express = require("express");
const mongoose = require("mongoose");
const dotenv = require("dotenv");
const cors = require("cors");
const cookieParser = require("cookie-parser");

const userRouter = require("./routes/user.route.js");
const authRouter = require("./routes/auth.route.js");
dotenv.config();
mongoose
  .connect(process.env.DB_CONNECTION)
  .then(() => {
    console.log("Mongo DB Coneccted");
  })
  .catch((err) => {
    console.log("Error Connecting Mongo DB", err);
  });

const app = express();
app.use(express.json());
// Enable CORS for all routes
app.use(cors({ origin: "http://localhost:3000", credentials: true }));
app.use(cookieParser());

app.listen(8000, () => {
  console.log("server is running on port 8000");
});


app.use("/api/v1/user", userRouter);
app.use("/api/v1/auth", authRouter);

app.use((err, req, res, next) => {
  const statusCode = err.statusCode || 500;
  const message = err.message || "Internal Server Error from Middleware";
  return res.status(statusCode).json({
    success: false,
    statusCode,
    message,
  });
});

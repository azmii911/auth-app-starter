const User = require("../models/user.model");
const bcryptjs = require("bcryptjs");
const { errorHandler } = require("../utils/error");
const jwt = require("jsonwebtoken");

const signup = async (req, res, next) => {
  const { firstName, lastName, email, password } = req.body;
  // Check if required fields are missing
  if (!firstName || !lastName || !email || !password) {
    return next(errorHandler(400, "All fields are required."));
  }

  const hashedPass = bcryptjs.hashSync(password, 10);
  const newUser = new User({
    firstName,
    lastName,
    email,
    password: hashedPass,
    phone: "",
    about: "",
  });

  try {
    // Check if the email is already in use
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return next(errorHandler(400, "Email is already in use."));
    }
    await newUser.save();
    res.status(201).json({
      message: "User Created Successfully!",
    });
  } catch (error) {
    next(error);
  }
};

const signin = async (req, res, next) => {
  // Extract email and password from the request body
  const { email, password } = req.body;

  if (!email || !password) {
    return next(errorHandler(400, "email, password are required."));
  }

  try {
    // Check if a user with the provided email exists
    const isValidUser = await User.findOne({ email });
    if (!isValidUser) {
      return next(errorHandler(404, `No user found as ${email}`));
    }

    // Compare the provided password with the hashed password in the database
    const validPassword = bcryptjs.compareSync(password, isValidUser.password);

    if (!validPassword) {
      return next(errorHandler(401, `Wrong Credentials`));
    }

    // Ensure that process.env.JWT_SECRET is properly set
    if (!process.env.JWT_SECRET) {
      console.error("JWT_SECRET is not set!");
      return next(errorHandler(500, "JWT_SECRET is not set"));
    }

    // Generate a JWT and exclude sensitive information from the response
    const token = jwt.sign({ id: isValidUser._id }, process.env.JWT_SECRET);

    // Exclude the password and other sensitive information from the response
    const { password: excludedPassword, ...otherInfo } = isValidUser._doc;

    res
      .cookie("access_token", token, { httpOnly: true })
      .status(200)
      .json(otherInfo);
  } catch (error) {
    next(error);
  }
};

const googleAuth = async (req, res, next) => {
  const { email, displayName, photoURL } = req.body;

  try {
    if (!email) {
      return next(errorHandler(400, "email is required."));
    }
    const isUser = await User.findOne({ email });

    if (isUser) {
      // Sign In User
      if (!process.env.JWT_SECRET) {
        console.error("JWT_SECRET is not set!");
        return next(errorHandler(500, "JWT_SECRET is not set"));
      }
      const token = jwt.sign({ id: isUser._id }, process.env.JWT_SECRET);
      const { password, ...otherInfo } = isUser._doc;

      res
        .cookie("access_token", token, { httpOnly: true })
        .status(200)
        .json(otherInfo);
    } else {
      // Creating User

      // Geneating New Password (Google do not send back pass)
      const generatedPassword = Math.random().toString(36).slice(-8);
      const hashedPassword = bcryptjs.hashSync(generatedPassword, 10);

      // extracting first and last Name
      const [firstName, lastName] = displayName.split(" ");

      const newUser = new User({
        firstName,
        lastName,
        email,
        avatar: photoURL,
        password: hashedPassword,
        phone: "",
        about: "",
      });
      await newUser.save();
      const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET);
      const { password, ...otherInfo } = newUser._doc;
      res
        .cookie("access_token", token, { httpOnly: true })
        .status(201)
        .json(otherInfo);
    }
  } catch (error) {
    next(error);
  }
};


const signOut =  (req, res, next) => {

  try {
    res.clearCookie("access_token").status(200).json({ message: "Logout Successfully" });
  } catch (error) {
    next(error)
  }

}
module.exports = { signup, signin, googleAuth, signOut };

const User = require("../models/user.model.js");
const { errorHandler } = require("../utils/error");
const bcryptjs = require("bcryptjs");

const updateUser = async (req, res, next) => {
  const { firstName, lastName, email, phone, password, newPassword, about } =
    req.body;

  const { id } = req.params;

  if (req.user.id !== req.params.id)
    return next(errorHandler(401, "You can only update your own account!"));

  try {
    // Retrieve the current user from the database
    const currentUser = await User.findById(id);

    // Check if the provided current password is correct
    if (password && !bcryptjs.compareSync(password, currentUser.password)) {
      return next(errorHandler(401, "Current password is incorrect."));
    }

    // Check if newPassword is provided and not null or empty
    if (newPassword !== null && newPassword !== "") {
      // Check if the new password is the same as the current password
      if (bcryptjs.compareSync(newPassword, currentUser.password)) {
        return next(
          errorHandler(
            400,
            "New password cannot be the same as the current password."
          )
        );
      }

      // Hash the new password
      const hashedNewPassword = bcryptjs.hashSync(newPassword, 10);

      // Update the user in the database
      const updatedUser = await User.findByIdAndUpdate(
        id,
        {
          $set: {
            firstName,
            lastName,
            email,
            phone,
            password: hashedNewPassword,
            about,
          },
        },
        { new: true }
      );

      // Exclude password from the response
      const { password: excludedPassword, ...otherInfo } = updatedUser._doc;

      // Send the updated user information in the response
      res.status(201).json(otherInfo);
    } else {
      // If newPassword is not provided, update other fields without changing the password
      const updatedUser = await User.findByIdAndUpdate(
        id,
        {
          $set: {
            firstName,
            lastName,
            email,
            phone,
            about,
          },
        },
        { new: true }
      );

      // Exclude password from the response
      const { password: excludedPassword, ...otherInfo } = updatedUser._doc;

      // Send the updated user information in the response
      res.status(201).json(otherInfo);
    }
  } catch (error) {
    next(error);
  }
};

module.exports = { updateUser };


const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  firstName: {
    type: String,
    required: true,
  },
  lastName: {
    type: String,
    required: false,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  phone: {
    type: String,
    required: false,
  },
  about: {
    type: String,
    required: false,
  },
  avatar:{
    type:String,
  }
}, {timestamps:true});

const User = mongoose.model('User', userSchema);

module.exports = User

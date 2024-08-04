const mongoose = require("mongoose");
const User = mongoose.model("User", {
  name: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    require: true,
    unique: true,
  },
  password: {
    type: String,
    require: true,
  },
  role: { type: String, default: "user" },
});

module.exports = User;

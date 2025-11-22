const { UsersModel: User } = require("../models/UsersModel");
const { createSecretToken } = require("../utils/SecretToken");
const bcrypt = require("bcryptjs");

const Signup = async (req, res) => {
  try {
    const { email, password, username, createdAt } = req.body;
    console.log("Incoming signup:", req.body);

    if (!email || !password || !username) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ success: false, message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = await User.create({
      email,
      password: hashedPassword,
      username,
      createdAt,
    });

    const token = createSecretToken(user._id);

    // ✅ Store token as cookie (makes user “logged in”)
    res.cookie("token", token, {
      httpOnly: true,
      secure: true, // use true if HTTPS
      sameSite: "None",
    });

    console.log("Signup successful, sending response...");

    // ✅ Return proper success response
    return res.status(201).json({
      success: true,
      message: "User signed up successfully",
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    console.error(error);
    return res.status(500).json({ success: false, message: "Signup failed", error: error.message });
  }
};

const Login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1️⃣ Check if email and password are provided
    if (!email || !password) {
      return res.status(400).json({ success: false, message: "All fields are required" });
    }

    // 2️⃣ Find the user by email
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(404).json({ success: false, message: "User does not exist" });
    }

    // 3️⃣ Compare the password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: "Incorrect password" });
    }

    // 4️⃣ Create JWT token
    const token = createSecretToken(user._id);

    // 5️⃣ Store token in cookie
    res.cookie("token", token, {
      httpOnly: true,
      secure: true, // true in production with HTTPS
      sameSite: "None",
    });

    // 6️⃣ Send response
    return res.status(200).json({
      success: true,
      message: "User logged in successfully",
      user: {
        _id: user._id,
        username: user.username,
        email: user.email,
      },
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({ success: false, message: "Login failed", error: error.message });
  }
};


const getUser = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password"); // omit password
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json({ success: true, user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Failed to get user", error: error.message });
  }
};

const Logout = async (req, res) => {
  try {
    res.clearCookie("token", {
      httpOnly: true,
      sameSite: "Lax",
      secure: true,
    });

    return res.status(200).json({ success: true, message: "Logged out" });
  } catch (error) {
    console.error("Logout error:", error);
    return res.status(500).json({ success: false, message: "Logout failed" });
  }
};

module.exports = { Signup, Login, getUser, Logout };

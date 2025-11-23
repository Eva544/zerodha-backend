const jwt = require("jsonwebtoken");

module.exports.verifyToken = (req, res, next) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res.status(401).json({ success: false, message: "No token found" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ success: false, message: "Invalid token" });
      }

      req.userId = decoded.id;
      next();
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: "Authorization failed" });
  }
};

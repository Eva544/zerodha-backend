const jwt = require("jsonwebtoken");

module.exports.verifyToken = (req, res, next) => {
  try {
    const token = req.cookies.token;

    if (!token) {
      return res.json({ status: false, message: "No token found" });
    }

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.json({ status: false, message: "Invalid token" });
      } else {
        req.userId = decoded.id;
        next();
      }
    });

  } catch (error) {
    console.error(error);
    res.json({ status: false, message: "Authorization failed" });
  }
};

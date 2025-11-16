const { Signup, Login, getUser, Logout } = require("../controllers/AuthController");
const { verifyToken } = require("../middlewares/AuthMiddleware");
const router = require("express").Router();

router.post("/signup", Signup);

router.post("/login", Login);

router.post("/logout", Logout);

router.get("/user/me", verifyToken, getUser); // protected route



module.exports = router;
const exppress = require("express");
const {
  signup,
  signin,
  googleAuth,
  signOut,
} = require("../controllers/auth.controller.js");

const router = exppress.Router();

router.post("/signup", signup);
router.post("/signin", signin);
router.post("/googleAuth", googleAuth);
router.get("/signout", signOut);

module.exports = router;

const { model } = require("mongoose");
const { UsersSchema } = require("../schemas/UsersSchema");

const UsersModel = model("users", UsersSchema);

module.exports = { UsersModel };

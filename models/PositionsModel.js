const { model } = require('mongoose');

const { PositionsSchema } = require('../schemas/PositionsSchema');

const PositionsModel = model('positions', PositionsSchema);

module.exports = { PositionsModel };
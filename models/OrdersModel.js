const { model } = require('mongoose');

const { OrdersSchema } = require('../schemas/OrdersSchema');

const OrdersModel = model('orders', OrdersSchema);

module.exports = { OrdersModel };
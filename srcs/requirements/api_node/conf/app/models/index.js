const dbConfig = require("../config/db.config");
const bcrypt = require('bcrypt');

const Sequelize = require("sequelize");
const sequelize = new Sequelize(dbConfig.DB, dbConfig.USER, dbConfig.PASSWORD, {
  host: dbConfig.HOST,
  dialect: dbConfig.dialect,
  operatorsAliases: 0,

  pool: {
    max: dbConfig.pool.max,
    min: dbConfig.pool.min,
    acquire: dbConfig.pool.acquire,
    idle: dbConfig.pool.idle
  },

  logging: false
});

const db = {};

db.Sequelize = Sequelize;
db.sequelize = sequelize;

db.users = require("./User")(sequelize, Sequelize);
db.refreshTokens = require("./RefreshToken")(sequelize, Sequelize);
db.resetTokens = require("./ResetToken")(sequelize, Sequelize);
db.confirmTokens = require("./ConfirmToken")(sequelize, Sequelize);

module.exports = db;

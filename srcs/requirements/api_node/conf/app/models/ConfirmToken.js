const { DataTypes } = require("sequelize");

module.exports = (sequelize, Sequelize) => {
    const ConfirmToken = sequelize.define('confirm_token', {
        token: {
            type: DataTypes.STRING(500),
            allowNull: false,
            unique: true
        },
        userId: {
            type: DataTypes.INTEGER,
            allowNull: false,
            unique: true
        },
        expiresAt: {
            type: DataTypes.DATE,
            allowNull: false
        }
    });
    return ConfirmToken;
};

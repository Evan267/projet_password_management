const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const helmet = require('helmet');
const cookieParser = require("cookie-parser");

const request = require("supertest");

const app = express();

app.set('trust proxy', true);

app.use(helmet());

app.use(cookieParser());

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', 'http://localhost:3000');
    res.setHeader('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content, Accept, Content-Type, Authorization');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS');
    next();
});

app.use(bodyParser.json());

const bcrypt = require('bcrypt');
const db = require('./models');
const User = db.users;
db.sequelize.sync({ force: true })
    .then(() => {
        console.log('Drop and re-sync db.');
    })
    .then(() => {
        bcrypt.hash('GroupoAdmin!63', 12)
        .then(hash => {
            let admin = {
            email: "auneor.PA@admin.com",
            password: hash,
            firstName: "Peche",
            lastName: "Aubergine",
            birthdate: new Date(1970, 1, 1),
            sex: "Homme",
            isAdmin: "true"
            };
            User.create(admin)
        })
        .catch(error => console.log(error));
    })

const userRoute = require('./routes/auth');
app.use('/api/auth', userRoute);

module.exports = app;

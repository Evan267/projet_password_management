const jwt = require('jsonwebtoken');
const { Sequelize } = require("../models");
const db = require("../models");
const Op = Sequelize.Op;
const User = db.users;

module.exports = (req, res, next) => {
  try {
    const { cookies, headers } = req;

    if (!cookies || !cookies.access_token) {
      return (res.status(401).json({message: "Token manquant dans les cookies" }))
    }

    const accessToken = cookies.access_token;

    if (!headers || !headers['x-xsrf-token']) {
      return (res.status(401).json({ message: "xsrf token manquant dans les headers"}))
    }

    const xsrfToken = headers['x-xsrf-token'];
    
    const decodedToken = jwt.verify(accessToken, process.env.TOKEN);
    if (xsrfToken !== decodedToken.csrf_token) {
      return (res.status(401).json({ message: "Mauvais xsrf token"}));
    }

    const decodedXsrf = jwt.verify(xsrfToken, process.env.TOKEN);
    const userId = decodedXsrf.userId;
    User.findOne({ attributes: ["birthdate", "email", "firstName", "lastName", "sex", "isConfirmed"], where: { id: userId, firstName: decodedToken.firstName, lastName: decodedToken.lastName }})
      .then(user => {
        if (!user) {
          return (res.status(401).json({ message: "Utilisateur introuvable" }))
        } else {
          res.locals.user = user;
          res.locals.userId = userId;
          next();
        }
      })
      .catch(() => res.status(500).json({ error: "Erreur serveur" }));
  } catch(err) {
    res.status(500).json({ error: "Erreur serveur" });
  }
};

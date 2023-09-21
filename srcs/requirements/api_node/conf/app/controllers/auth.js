const { Sequelize } = require("../models");
const db = require("../models");
const Op = Sequelize.Op;
const User = db.users;
const RefreshToken = db.refreshTokens;
const ResetToken = db.resetTokens;
const ConfirmToken = db.confirmTokens;

const bcrypt = require('bcrypt');
const jwt =  require('jsonwebtoken');
const sgMail = require('@sendgrid/mail');
const nodemailer = require('nodemailer');
const { validate } = require('deep-email-validator');
const longCookies = 43200000;
const shortCookies = 1800000;
const veryShortToken = 600000;

//initialisation Nodemailer
let transporter = nodemailer.createTransport({
  host: 'smtp.mail.ovh.net',
  port: 587,
  secure: false,
  auth: {
    user: process.env.EMAIL_PA,
    pass: process.env.PASSWORD_PA
  },
  tls:{
    ciphers:'SSLv3'
  }
});

function defineCookiesToken(refreshToken, user, csrf_token, res) {
  res.cookie('access_token', jwt.sign({ firstName:user.firstName, lastName: user.lastName, csrf_token }, process.env.TOKEN, { expiresIn: 1800000 }), 
  {
    maxAge: shortCookies,
    httpOnly: true,
    secure: true,
  });
  res.cookie('refresh_token', refreshToken, {
    maxAge: longCookies,
    path: '/token',
    httpOnly: true,
    secure: true,
  });
  return (res.status(201).json({ message: 'Connecté avec succès', csrf_token, accessTokenExpires: Date.now() + shortCookies, refreshTokenExpires: Date.now() + longCookies }));
}

function generateToken (user, res) {
  if (!user) {
    return (res.status(500).json({message: "Pas d'utilisateur pour la creation des token"}))
  }

  if (!res) {
    return (res.status(500).json({ message: "contacter Support client"}));
  }
  //csrf_token
  const csrf_token = jwt.sign(
    {
      userId: user.id,
      firstName: user.firstName,
      lastName: user.lastName,
    },
    process.env.TOKEN,
    { expiresIn: shortCookies}
  );
  //refresh token 
  const refreshToken = jwt.sign(
    {
      id: user.id
    },
    process.env.REFRESH_TOKEN,
    { expiresIn: longCookies}
  );
  RefreshToken.findOne({ where: { userId: user.id }})
    .then(userData => {
      if (!userData) {
        RefreshToken.create({
          userId: user.id,
          token: refreshToken,
          expiresAt: Date.now() + longCookies
        });
        return defineCookiesToken(refreshToken, user, csrf_token, res);
      } else {
        RefreshToken.update({
          token: refreshToken,
          expiresAt: Date.now() + longCookies
        }, { where: { userId: user.id }});
        return defineCookiesToken(refreshToken, user, csrf_token, res);
      }
    })
    .catch(() => res.status(500).json({ message: "Erreur serveur" }));
};

function sendResetMail (user, dbToken, email, res) {
  const resetToken = jwt.sign(
    {
      id: user.id,
      lastName: user.lastName,
      firstName: user.firstName,
      dbToken
    },
    process.env.RESET_TOKEN,
    { expiresIn: veryShortToken }
  );
  const mailOptions = {
    to: email,
    from: process.env.EMAIL_PA,
    subject: 'Mail de changement de mot de passe',
    text: 'Cliquer ici pour changer de mot de passe',
    html: `<a href="https://pecheaubergine.com/reset_password/${resetToken}">Cliquer ici pour changer de mot de passe</a>`,
  }
  transporter.sendMail(mailOptions)
    .then(() => res.status(200).json({ message: "Envoie de l'email reussi", resetToken }))
    .catch(() => res.status(500).json({ message: "Erreur du serveur" }));
}

function sendConfirmMail (user, dbToken, res, next, execNext) {
  const confirmToken = jwt.sign(
    {
      lastName: user.lastName,
      firstName: user.firstName,
      dbToken
    },
    process.env.TOKEN,
    { expiresIn: veryShortToken }
  );
  const mailOptions = {
    to: user.email,
    from: process.env.EMAIL_PA,
    subject: 'Confirmation de votre adresse mail pour votre inscription au site Peche & Aubergine',
    text: 'Bienvenue, Votre compte sur le site pecheaubergine.com a bien ete creer.',
    html: `<strong>Bienvenue sur le site Peche et Aubergine,</strong><br/><p>Pour confirmer votre compte veuillez <a href="https://pecheaubergine.com/confirm_password/${confirmToken}">cliquer ici</a></p>`,
  }
  transporter.sendMail(mailOptions)
    .then(() => {
      if (execNext) {
        next();
      } else {
        return (res.status(201).json({ message: "Le mail de confirmation a bien ete envoye" }));
      }
    })
    .catch(error => res.status(500).json({ message: "Erreur d'envoi de l'email", error }));
}

//POST
exports.logIn = (req, res, next) => {
  const { email, password } = req.body;
  
  User.findOne({ where: { email } })
    .then(user => {
      if (!user) {
        return res.status(400).json({ message: 'Email incorrect' });
      }
      bcrypt.compare(password, user.password)
        .then(valid => {
          if (!valid) {
            return res.status(400).json({ message: "Mot de passe incorrect" });
          }
          return (generateToken(user, res));
        })
        .catch(() => res.status(500).json({ message: "Erreur serveur" }));
    })
    .catch(() => res.status(500).json({ message: "Erreur serveur"}))
};

exports.signUp  = (req, res, next) => {
    const {email, password, firstName, lastName, sex, birthdate } = req.body;

    if (!email || !password || !firstName || !lastName || !sex || !birthdate) {
      return (res.status(400).json({ message: "Veuillez renseigner tous les champs" }))
    }
    // Test de l'adresse mail
    validate({
      email: email,
      sender: email,
      validateRegex: true,
      validateMx: true,
      validateTypo: true,
      validateDisposable: true,
      validateSMTP: email.includes('@gmail.com'),
    })
      .then(data => {
        if (!data.valid) {
          return res.status(400).json({ message: "Adresse mail inexistant" });
        } else {
          // Hachage du mot de passe
          bcrypt.hash(password, 10)
            .then(hash => {
              const user = {
                email: email,
                password: hash,
                firstName: firstName,
                lastName: lastName,
                sex: sex,
                birthdate: birthdate
              };
              User.create(user)
                .then(data => {
                  const dbToken = jwt.sign(
                    {
                      email: data.email,
                      lastName: data.lastName,
                      firstName: data.firstName,
                    },
                    process.env.CONFIRM_TOKEN,
                    { expiresIn: veryShortToken }
                  );
                  ConfirmToken.create({
                    userId: data.id,
                    token: dbToken,
                    expiresAt: Date.now() + veryShortToken
                  })
                    .then(() => sendConfirmMail(user, dbToken, res, next, 1))
                    .catch(() => res.status(500).json({ message: "Erreur dans l'enregistrement du token de confirmation" }))
                })
                .catch(error => {
                  const errArr = [];
                  let i = 0;
                  error.errors.map(er => {
                    errArr[i] = er.message;
                    i++;
                  });
                  res.status(400).json({ message: errArr[0] })});
          })
          .catch(() => res.status(500).json({ message: "Erreur serveur" })); 
        }
      })
      .catch(() => res.status(500).json({ message: "Erreur serveur" }));  
};

exports.resendConfirmationMail = (req, res, next) => {
  const email = res.locals.user.email;
  User.findOne({ where: { email: email } })
    .then(user => {
      if (!user) {
        return (res.status(400).json({ message: "Utilisateur introuvable" }));
      } else {
        const dbToken = jwt.sign(
          {
            email: user.email,
            lastName: user.lastName,
            firstName: user.firstName,
          },
          process.env.CONFIRM_TOKEN,
          { expiresIn: veryShortToken }
        );
        ConfirmToken.findOne({ where: { userId: user.id }})
          .then(tokenData => {
            if (!tokenData) {
              ConfirmToken.create({
                userId: user.id,
                token: dbToken,
                expiresAt: Date.now() + veryShortToken
              });
              return (sendConfirmMail(user, dbToken, res, next, 0));
            } else {
              ConfirmToken.update({
                token: dbToken,
                expiresAt: Date.now() + veryShortToken
              }, { where: { userId: user.id }});
              return (sendConfirmMail(user, dbToken, res, next, 0));
            }
          })
          .catch(() => res.status(500).json({ message: "Erreur serveur 1" }));
      }
    })
    .catch(() => res.status(500).json({ message: "Erreur serveur 2" }));
}

//GET
exports.refreshToken = (req, res, next) => {
    const { cookies } = req;
    const now = Date.now();
    console.log(cookies.refresh_token);
    if (!cookies || !cookies.refresh_token) {
      return (res.status(400).json({message: "pas de token de rafraichissement dans les cookies" }))
    }
    const decodedToken = jwt.verify(cookies.refresh_token, process.env.REFRESH_TOKEN);
    const userId = decodedToken.id;
    RefreshToken.findOne({where: { userId: userId, token: cookies.refresh_token }})
      .then(data => {
          if (!data || now > data.expiresAt.getTime()) {
            return res.status(401).json({ message: 'token invalide' });
          } else {
            User.findOne({ attributes: ["id", "birthdate", "email", "firstName", "lastName", "sex"], where: { id: userId }})
              .then(user => {
                if (!user) {
                  return (res.status(401).json({ message: "Utilisateur introuvable" }))
                } else {
                  return (generateToken(user, res));
                }
            })
            .catch(() => res.status(500).json({ error: "Erreur serveur" }));
        }
      })
      .catch(() => res.status(500).json({ message: "Erreur Serveur" }));
}

exports.getUser = (req, res, next) => {
  return (res.status(200).json({user: res.locals.user}));
}

//PUT
exports.modifyUser = (req,res, next) => {
    const {email, firstName, lastName, sex, birthdate } = req.body;
    const userId = res.locals.userId;
    validate(email)
      .then(data => {
        if (!data.valid) {
          return res.status(401).json({ error: "Adresse mail inexistant" });
        } else {
          const user = {
            id: userId,
            email: email,
            firstName: firstName,
            lastName: lastName,
            birthdate: birthdate,
            sex: sex,
          };
          User.update(user, { where: { id: userId }})
            .then(() => generateToken(user, res))
            .catch (error => res.status(400).json({error}));
        }})
      .catch(() => res.status(500).json({ message: "Erreur serveur" }));
}

exports.confirm = (req,res) => {
  const token = req.params.token;
  const decodedToken = jwt.verify(token, process.env.TOKEN);
  const dbToken = decodedToken.dbToken;
  const decodedDbToken = jwt.verify(dbToken, process.env.CONFIRM_TOKEN);
  ConfirmToken.findOne({ where: { token: dbToken }})
    .then(data => {
      if (!data) {
        return (res.status(400).json({ message: "token introuvable" }));
      } else if (data.expiresAt.getTime < Date.now()) {
        return (res.status(400).json({ message: "Temps expire" }));
      } else {
        User.update({isConfirmed: "true" }, { where: { email: decodedDbToken.email } })
          .then(() => {
            data.destroy()
              .then(() => res.status(200).json({ message: "Compte confirmer" }))
              .catch(() => res.status(500).json({ message: "Erreur serveur" }));
          })
          .catch(() => res.status(500).json({ message: "Erreur serveur" }));
      }
    })
    .catch(() => res.status(500).json({ message: "Erreur serveur" }));
}

//DELETE
exports.deleteUser = (req, res, next) => {
  const { password } = req.body;
  const userId = res.locals.userId;
  User.findOne({ where: { id: userId }})
      .then(user => {
        if (!user) {
          return res.status(401).json({ message: 'Utilisateur introuvable' });
        }
        bcrypt.compare(password, user.password)
          .then(valid => {
            if (!valid) {
              return res.status(401).json({ error: "Mot de passe incorrect !" });
            }
            user.destroy()
              .then(() => res.status(200).json({ message: 'Utilisateur supprimé !'}))
              .catch(() => res.status(500).json({ message: "Erreur serveur" }));
          })
          .catch(() => res.status(500).json({ message: "Erreur serveur" }));
      })
      .catch(() => res.status(500).json({ message: "Erreur Serveur" }));
}

//PASSWORD RESET
exports.passwordResetMail = (req, res, next) => {
  const { email } = req.body;
  User.findOne({ where: { email: email }})
    .then(data => {
      console.log(data);
      if (!data) {
        return res.status(401).json({ message: 'Utilisateur introuvable' });
      } else {
        const dbToken = jwt.sign(
          {
            email: data.email,
            lastName: data.lastName,
            firstName: data.firstName,
          },
          process.env.TOKEN,
          { expiresIn: veryShortToken }
        );
        ResetToken.findOne({ where: { userId: data.id }})
          .then(tokenData => {
            if (!tokenData) {
              ResetToken.create({
                userId: data.id,
                token: dbToken,
                expiresAt: Date.now() + veryShortToken
              })
                .then(() => sendResetMail(data, dbToken, email, res))
                .catch(() => res.status(500).json({ message: "Erreur serveur" }));
            } else {
              ResetToken.update({
                token: dbToken,
                expiresAt: Date.now() + veryShortToken
              }, { where: { userId: data.id }})
                .then(() => sendResetMail(data, dbToken, email, res))
                .catch(() => res.status(500).json({ message: "Erreur serveur" }));
            }
          })
          .catch(() => res.status(500).json({ message: "Erreur serveur" }));
      }})
    .catch(() => res.status(500).json({ message: "Erreur serveur" }));
}

exports.passwordReset = (req, res, next) => {
  const token = req.params.token;
  const decodedToken = jwt.verify(token, process.env.RESET_TOKEN);
  const dbToken = decodedToken.dbToken;
  const decodeddbToken = jwt.verify(dbToken, process.env.TOKEN);
  const password = req.body.password;
  const email = decodeddbToken.email;
  ResetToken.findOne({ where: { token: dbToken, userId: decodedToken.id } })
    .then(resetToken => {
      if (!resetToken) {
        return res.status(400).json({ message: "token inconnu" });
      } else if (resetToken.expiresAt.getTime() < Date.now()) {
        return res.status(401).json({ message: "Date d'expiration du token depasser" });
      } else {
        bcrypt.hash(password, 10)
          .then(hash => {
            User.update({ password: hash}, { where: { id: decodedToken.id } })
              .then(user => {
                if (!user) {
                  return res.status(400).json({ message: "Utilisateur introuvable" })
                } else {
                  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
                  const msg = {
                    to: email,
                    from: process.env.EMAIL_PA,
                    subject: 'Votre mot de passe a bien été modifié',
                    text: 'Suite à votre demande, votre mot de passe a bien été modifié',
                    html: `<p>Suite à votre demande, votre mot de passe a bien été modifié</p>`,
                  }
                  sgMail.send(msg)
                    .then(() => res.status(200).json({ message: "Envoie de l'email reussi" }))
                    .catch(() => res.status(501).json({ message: "Erreur serveur" }));
                }
              })
              .catch(() => res.status(500).json({ message: "Erreur serveur" }));
          })
          .catch(() => res.status(500).json({ message: "Erreur serveur" }));
      }
    })
    .catch(() => res.status(500).json({ message: "Erreur serveur" }));
}

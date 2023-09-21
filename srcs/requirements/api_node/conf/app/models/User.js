const { DataTypes } = require("sequelize");

module.exports = (sequelize, Sequelize) => {
    const User = sequelize.define('user', {
        email: {
            type: DataTypes.STRING(100),
            allowNull: false,
            unique:  {
              arg: true,
              msg: 'Cet email est deja utilise'
            },
            validate: {
              isEmail: true,
              notEmpty:  true,
	          }
        },
        password: {
            type: DataTypes.STRING(100),
            allowNull: false
        },
        firstName: {
            type: DataTypes.STRING(80),
            allowNull: false,
            validate: {
              is: {
                args: /^[a-zA-Z-']+$/,
                msg: 'Le champ prénom n\'accepte que les lettres minuscule, majuscule, les tirets et les apostrophes simples'
              },
              len: {
                args: [1, 80],
                msg: 'Le champ prénom doit faire minimum 1 caracteres et maximum 80 caracteres'
              },
              notEmpty: true,
              notNull: true,
	          }
        },
        lastName: {
            type: DataTypes.STRING(80),
            allowNull: false,
            validate: {
              is: {
                args: /^[a-zA-Z-']+$/,
                msg: 'Le champ nom n\'accepte que les lettres minuscule, majuscule, les tirets et les apostrophes simples'
              },
              len: {
                args: [1, 80],
                msg: 'Le champ nom doit faire minimum 1 caracteres et maximum 80 caracteres'
              },
              notEmpty: true,
              notNull: true,
	          }
        },
        sex: {
            type: DataTypes.ENUM("Homme", "Femme"),
            allowNull: false,
            validate: {
              isIn: {
                args: [['Homme', 'Femme']],
                msg: 'La valeur du champ sexe doit etre Homme ou Femme'
              }
            }
        },
        birthdate: {
            type: DataTypes.DATEONLY,
            validate: {
              /*isDate: {
                arg: true,
                msg: "Le format de la date est incorrect"
              },*/
              is: {
                args: /^(?:(?:19|20)[0-9]{2}[\-](?:(?:0[1-9]|1[0-2])[\-](?:0[1-9]|1[0-9]|2[0-9])|(?:0[13-9]|1[0-2])[\-](?:30)|(?:0[13578]|1[02])[\-](?:31)))$/,
                msg: "Le format de la date est incorrect"
              },
              isOver18(value) {
                const today = new Date();
                const birthdate = new Date(value);
                const age = today.getFullYear() - birthdate.getFullYear();
                const monthDiff = today.getMonth() - birthdate.getMonth();
                const dayDiff = today.getDay() - birthdate.getDay();
                if (age < 18 || (age == 18 && monthDiff < 0) || (age == 18 && monthDiff >= 0 && dayDiff <= 0)) {
                  throw new Error('La personne doit avoir plus de 18 ans');
                }
              }
	          }
        },
        isAdmin: {
            type: DataTypes.STRING,
            defaultValue: "false"
        },
        isConfirmed: {
          type: DataTypes.STRING,
          defaultValue: "false"
        },
        isBlocked: {
            type: DataTypes.STRING,
            defaultValue: "false"
        }
    });
    return User;
};

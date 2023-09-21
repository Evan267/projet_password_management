module.exports = (req, res, next) => {
    const { password } = req.body;
    const regex = /(?=.*\d)(?=.*[!@#$&*])(?=.*[a-z])(?=.*[A-Z]).{8,}/;
    const checkPassword = regex.test(password);
    if(checkPassword == true && password.length > 100){
        return res.status(400).json({ message: 'Veuillez utiliser un mot de passe de moins de 100 caractères' });
    } else if (checkPassword == true) {
        next();
    } else {
        return res.status(400).json({ message: 'Veuillez utiliser au moins 1 majuscule, 1 minuscule, 1 chiffre, 1 caractère spécial et au moins 8 caractères.' });
    }
};

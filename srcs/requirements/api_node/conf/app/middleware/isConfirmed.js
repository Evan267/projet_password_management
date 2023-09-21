module.exports = (req, res, next) => {
    const { isConfirmed } = res.locals.user;
    if (isConfirmed == "true") {
        next();
    } else {
        return (res.status(400).json({ message: "Veuillez confirmer votre compte" }));
    }
};

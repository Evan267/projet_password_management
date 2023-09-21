module.exports = (req, res, next) => {
    const { recaptcha } = req.body;
    if (recaptcha === "" || recaptcha === undefined || recaptcha === null) {
        return res.json(406).json({ message: "Capatcha vide" });
    }

    const url = `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptcha}&remoteip=${req.ip}`;
    console.log(url);
    fetch(url, {
        method: "post"
    })
        .then(response => response.json())
        .then(google_response => {
            if (google_response.success == true) {
                next();
            } else {
                return res.status(407).json({ message: "Captcha incorrect", google_response });
            }
        })
        .catch(error => res.status(500).json({ message: "Erreur serveur", error }));
};

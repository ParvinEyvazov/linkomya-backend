const nodemailer = require("nodemailer");

//constants
const HOST = process.env.HOST;
const MAIL_USER = process.env.MAIL_USER;
const MAIL_PASSWORD = process.env.MAIL_PASSWORD;

export async function sendEmail(req, res) {
    const { email, subject, message } = req.body;

    if (email && subject && message) {
        //creating transport

        //real
        // var transporter = nodemailer.createTransport({
        //     direct: true,
        //     host: `${HOST}`,
        //     port: 465,
        //     auth: {
        //         user: `${MAIL_USER}`,
        //         pass: `${MAIL_PASSWORD}`
        //     },
        //     secure: true
        // });

        var transporter = nodemailer.createTransport({
            host: "smtp.mailtrap.io",
            port: 2525,
            auth: {
                user: "0ee0caae1c77e0",
                pass: "1fbcff2c172f96"
            }
        });

        var mailOption = {
            from: "0ee0caae1c77e0",
            to: email,
            subject: subject,
            html: "<h1>" + message + "</h1>"
        };

        transporter.sendMail(mailOption, function(error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log("Email sent: ", info.response);
            }
        });

        res.status(200).send({ message: "Process Completed." });
    } else {
        res.status(400).send({ message: "Target email, subject or message is empty." });
    }
}

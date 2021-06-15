import * as Bucket from "@spica-devkit/bucket";

const jwt = require("jsonwebtoken");
const cookie = require("cookie");
var bcrypt = require("@node-rs/bcrypt");
const fetch = require("node-fetch");
var uuid = require("uuid-random");
var Buffer = require("buffer/").Buffer;

// constants
const AUTHORIZATION_TTL = 6 * 60 * 60;
const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;
const SECRET_API_KEY = process.env.SECRET_API_KEY;
const USER_BUCKET_ID = process.env.USER_BUCKET_ID;
const USER_AUTHENTICATION_BUCKET_ID = process.env.USER_AUTHENTICATION_BUCKET_ID;
const MAIL_TEMPLATE_BUCKET_ID = process.env.MAIL_TEMPLATE_BUCKET_ID;
const AUTH_CODE_BUCKET_ID = process.env.AUTH_CODE_BUCKET_ID;
const SYSTEM_NAME = process.env.SYSTEM_NAME;
const DOMAIN = process.env.DOMAIN;
const PASSWORD_RECOVERY_AUTH_CODE_BUCKET_ID = process.env.PASSWORD_RECOVERY_AUTH_CODE_BUCKET_ID;
const SYSTEM_LOGO = "https://i.hizliresim.com/jm99oJ.png";

//--------LOGIN--------
export async function login(req, res) {
    //get email and password from body
    const { email } = req.body;
    const password = await decode(req.body.password);

    //if email and password is not empty | undefined
    if (email && password) {
        if (isValidEmail(email)) {
            if (isValidPassword(req.body.password)) {
                //initialize Bucket
                Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

                //get user auth info with this email
                const userAuthArray = await Bucket.data.getAll(`${USER_AUTHENTICATION_BUCKET_ID}`, {
                    queryParams: {
                        filter: {
                            email: email
                        }
                    }
                });

                //if there is a user with this email address
                if (userAuthArray.length > 0) {
                    const userAuth = userAuthArray[0];
                    var passwordMatches = await bcrypt.verify(password, userAuth.password);

                    //if passwords matches
                    if (passwordMatches) {
                        //get this user all information
                        const userArray = await Bucket.data.getAll(`${USER_BUCKET_ID}`, {
                            queryParams: {
                                filter: {
                                    _id: userAuth.user
                                }
                            }
                        });

                        //if there is a user with this authentication
                        if (userArray.length > 0) {
                            const user = userArray[0];

                            const test_date = new Date(userAuth.jwt_expiration_date);

                            //create token
                            const token = await jwt.sign(
                                {
                                    _id: user._id,
                                    username: user.username,
                                    fullname: user.fullname
                                },
                                `${JWT_SECRET_KEY}`,
                                {
                                    expiresIn: `${AUTHORIZATION_TTL}s`,
                                    header: {
                                        _id: user._id,
                                        username: user.username
                                    }
                                }
                            );

                            //set token to cookie
                            res.headers.set(
                                "Set-Cookie",
                                cookie.serialize("Authorization", token, {
                                    domain: `${DOMAIN}`,
                                    path: "/",
                                    maxAge: AUTHORIZATION_TTL,
                                    sameSite: "none",
                                    secure: true
                                })
                            );

                            //return success message
                            return res.status(200).send({
                                message:
                                    "Successfully logged in. It is nice to see you " +
                                    user.fullname,
                                jwt_auth: {
                                    jwt_token: token,
                                    expire: 720
                                },
                                user_id: user._id,
                                fullname: user.fullname,
                                username: user.username
                            });
                        }
                    }
                    //if password is wrong
                    else {
                        res.status(400).send({
                            message: "Password is wrong.",
                            error_type: "login_failed"
                        });
                    }
                }

                //if there is not a user like that
                else {
                    res.status(400).send({
                        message: "Email and password is wrong.",
                        error_type: "login_failed"
                    });
                }
            }
            // if email is not valid
            else {
                res.status(400).send({
                    message: "Password must be at least 6 characters.",
                    error_type: "login_failed"
                });
            }
        }
        //if password is not valid
        else {
            res.status(400).send({
                message: "Invalid Email address.",
                error_type: "login_failed"
            });
        }
    }
    //if email and password is empty | undefined
    else {
        res.status(400).send({
            message: "Email or password is undefined.",
            error_type: "login_failed"
        });
    }
}

export async function logout(req, res) {
    res.headers.set(
        "Set-Cookie",
        cookie.serialize("Authorization", "", {
            domain: DOMAIN,
            path: "/",
            expires: new Date()
        })
    );
    res.status(201).send({});
}

//--------REGISTER--------SEND CODE
export async function registerSendCode(req, res) {
    const trace_id = Math.random() * 1000000000;
    const { email, fullname } = req.body;
    const password = await decode(req.body.password);

    let respondOfBucketInitialize = await Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

    if (email && fullname && password) {
        if (isValidFullname(fullname)) {
            if (isValidEmail(email)) {
                if (isValidPassword(req.body.password)) {
                    const check_email = await Bucket.data.getAll(
                        `${USER_AUTHENTICATION_BUCKET_ID}`,
                        {
                            queryParams: {
                                filter: {
                                    email: email
                                }
                            }
                        }
                    );

                    //if this email is already exist
                    if (check_email.length > 0) {
                        res.status(400).send({
                            message: "A user has already registered with this e-mail address.",
                            error_type: "registered_user"
                        });
                    }
                    //if email does not exist
                    else {
                        // Mail will send code
                        let auth_code = Math.floor(100000 + Math.random() * 900000).toString();

                        sendRegisterEmail(email, auth_code, trace_id)
                            .then(async () => {
                                let passs = await bcrypt.hash(password, 10);

                                await Bucket.data
                                    .insert(`5f78a88aee1a44008d3c37f4`, {
                                        trace_id: `${trace_id}`,
                                        code: `${auth_code}`,
                                        email: email,
                                        password: await bcrypt.hash(password, 10),
                                        fullname: fullname
                                    })
                                    .then(() => {})
                                    .catch(err => {
                                        console.log("error ", err);
                                    });
                            })
                            .then(() => {
                                res.status(200).send({
                                    message:
                                        "We sent a 6-digit code to your mail address. Please enter the 6-digit code here.",
                                    message_type: "waiting_verification",
                                    trace_id: trace_id
                                    // auth_code: Buffer.from(auth_code).toString("base64")
                                });
                            })
                            .catch(error => {
                                console.log(email, " Mail error", error);
                                res.status(400).send({
                                    message:
                                        "We couldn`t complete the process. Please try few monites later again. Or contact us and provide the trace ID: " +
                                        trace_id,
                                    error_type: "unknown_error"
                                });
                            });
                    }
                }
                // if password is not valid
                else {
                    res.status(400).send({
                        message: "Password must be at least 6 characters.",
                        error_type: "login_failed"
                    });
                }
            }
            // if email is not valid
            else {
                res.status(400).send({
                    message: "Invalid Email address.",
                    error_type: "login_failed"
                });
            }
        }
        //if fullname is not valid
        else {
            res.status(400).send({
                message: "Invalid Fullname.",
                error_type: "login_failed"
            });
        }
    }
    // undefined email or name or surname or password
    else {
        res.status(400).send({
            message: "Please fill all the required inputs.",
            error_type: "required_field"
        });
    }
}

//--------REGISTER--------SEND MAIL FUNCTION
export async function sendRegisterEmail(email, auth_code, trace_id) {
    const mail_template_array = await Bucket.data.getAll(`${MAIL_TEMPLATE_BUCKET_ID}`, {
        queryParams: {
            filter: {
                name: "register"
            }
        }
    });

    //update email informations
    let mail_template = mail_template_array[0].template;
    mail_template = mail_template.replace("_SYSTEM_LOGO_URL_", SYSTEM_LOGO);
    mail_template = mail_template.replace("_SYSTEM_NAME_", SYSTEM_NAME);
    mail_template = mail_template.replace("_AUTH_CODE_", auth_code);

    // await fetch("http://localhost:4500/api/fn-execute/sendEmail", {
    await fetch("https://talent-fdb6f.hq.spicaengine.com/api/fn-execute/sendEmail", {
        method: "post",
        body: JSON.stringify({
            email: email,
            subject: "Two factor authentication",
            message: mail_template
        }),
        headers: {
            "Content-Type": "application/json"
        }
    });
}

//--------REGISTER--------VALIDATE CODE
export async function registerValidateCode(req, res) {
    const { email, fullname, trace_id, auth_code } = req.body;
    const password = await decode(req.body.password);
    Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

    if (email && fullname && password && trace_id && auth_code) {
        if (isValidFullname(fullname)) {
            if (isValidEmail(email)) {
                if (isValidPassword(req.body.password)) {
                    const check_email = await Bucket.data.getAll(
                        `${USER_AUTHENTICATION_BUCKET_ID}`,
                        {
                            queryParams: {
                                filter: {
                                    email: email
                                }
                            }
                        }
                    );

                    if (check_email.length > 0) {
                        res.status(400).send({
                            message: "A user has already registered with this e-mail address.",
                            error_type: "registered_user"
                        });
                    } else {
                        const auth_code_array = await Bucket.data.getAll(`${AUTH_CODE_BUCKET_ID}`, {
                            queryParams: {
                                filter: {
                                    trace_id: trace_id
                                }
                            }
                        });

                        //not correct auth code
                        if (auth_code_array.length > 0) {
                            var passwordMatches = await bcrypt.verify(
                                password,
                                auth_code_array[0].password
                            );

                            if (auth_code_array[0].code != req.body.auth_code) {
                                res.status(400).send({
                                    message: "E-mail validation failed.",
                                    error_type: "wrong_code"
                                });
                            }
                            //email, password or fullname is different before authenticating
                            else if (
                                email != auth_code_array[0].email ||
                                fullname != auth_code_array[0].fullname ||
                                !passwordMatches
                            ) {
                                res.status(400).send({
                                    message:
                                        "E-mail or full Name or password has changed while authenticating.",
                                    error_type: "changed_info"
                                });
                            } else {
                                //save to database
                                await Bucket.data
                                    .insert(`${USER_BUCKET_ID}`, {
                                        fullname: fullname
                                    })
                                    .then(async data => {
                                        await Bucket.data
                                            .insert(`${USER_AUTHENTICATION_BUCKET_ID}`, {
                                                email: email,
                                                password: await bcrypt.hash(password, 10),
                                                user: data._id
                                            })
                                            .then(() => {
                                                res.status(200).send({
                                                    message: "Great! You just registered.",
                                                    message_type: "success"
                                                });
                                            })
                                            .catch(async error => {
                                                console.log(
                                                    trace_id,
                                                    " Couldn`t insert a new user to DB of AUTH"
                                                );
                                                await Bucket.data.remove(
                                                    `${USER_BUCKET_ID}`,
                                                    data._id
                                                );
                                                res.status(400).send({
                                                    message:
                                                        "We couldn`t complete the process. Please try few minutes later again. You can contact us and provide the trace ID: " +
                                                        trace_id,
                                                    error_type: "unknown_error"
                                                });
                                            });
                                    })
                                    .catch(error => {
                                        console.log(
                                            trace_id,
                                            " Couldn`t insert a new user to DB ",
                                            error
                                        );
                                        res.status(400).send({
                                            message:
                                                "We couldn`t complete the process. Please try few minutes later again. You can contact us and provide the trace ID: " +
                                                trace_id,
                                            error_type: "unknown_error"
                                        });
                                    });
                            }
                        } else {
                            res.status(400).send({
                                message: "Wrong trace_id.",
                                error_type: "wrong_trace_id"
                            });
                        }
                    }
                } else {
                    res.status(400).send({
                        message: "Password must be at least 6 characters.",
                        error_type: "login_failed"
                    });
                }
            } else {
                res.status(400).send({
                    message: "Invalid Email address.",
                    error_type: "login_failed"
                });
            }
        } else {
            res.status(400).send({
                message: "Invalid Fullname.",
                error_type: "login_failed"
            });
        }

        //*
    }
    // undefined email or fullname or password
    else {
        res.status(400).send({
            message: "Please fill all the required inputs.",
            error_type: "required_field"
        });
    }
}

//--------PASSWORD RECOVERY--------SEND CODE
export async function passwordRecoverySendCode(req, res) {
    const trace_id = Math.random() * 1000000000;
    const { email } = req.body;

    Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

    if (email) {
        if (isValidEmail(email)) {
            const check_email = await Bucket.data.getAll(`${USER_AUTHENTICATION_BUCKET_ID}`, {
                queryParams: {
                    filter: {
                        email: email
                    }
                }
            });

            //if there is an account with this email
            if (check_email.length > 0) {
                // Mail will send code
                let auth_code = Math.floor(100000 + Math.random() * 900000).toString();

                sendPasswordRecoveryEmail(email, auth_code, trace_id)
                    .then(async () => {
                        return Bucket.data.insert(`${PASSWORD_RECOVERY_AUTH_CODE_BUCKET_ID}`, {
                            trace_id: `${trace_id}`,
                            code: `${auth_code}`,
                            email: email
                        });
                    })
                    .then(() => {
                        res.status(200).send({
                            message:
                                "We sent a 6-digit code to your mail address. Please enter the 6-digit code here.",
                            message_type: "waiting_verification",
                            trace_id: trace_id
                        });
                    })
                    .catch(error => {
                        console.log(email, " Mail error", error);
                        res.status(400).send({
                            message:
                                "We couldn`t complete the process. Please try few monites later again. Or contact us and provide the trace ID: " +
                                trace_id,
                            error_type: "unknown_error"
                        });
                    });
            }
            //if there is not any email in the system
            else {
                res.status(400).send({
                    message: "There is not any account with this email.",
                    error_type: "unknown_email"
                });
            }
        } else {
            res.status(400).send({
                message: "Invalid Email address.",
                error_type: "login_failed"
            });
        }
    }
    // undefined email
    else {
        res.status(400).send({
            message: "Please fill all the required inputs.",
            error_type: "required_field"
        });
    }
}

//--------PASSWORD RECOVERY--------SEND MAIL FUNCTION
export async function sendPasswordRecoveryEmail(email, auth_code, trace_id) {
    const mail_template_array = await Bucket.data.getAll(`${MAIL_TEMPLATE_BUCKET_ID}`, {
        queryParams: {
            filter: {
                name: "password_recovery"
            }
        }
    });

    //update email informations
    let mail_template = mail_template_array[0].template;
    mail_template = mail_template.replace("_SYSTEM_LOGO_URL_", SYSTEM_LOGO);
    mail_template = mail_template.replace("_SYSTEM_NAME_", SYSTEM_NAME);
    mail_template = mail_template.replace("_AUTH_CODE_", auth_code);

    // await fetch("http://localhost:4500/api/fn-execute/sendEmail", {
    await fetch("https://talent-fdb6f.hq.spicaengine.com/api/fn-execute/sendEmail", {
        method: "post",
        body: JSON.stringify({
            email: email,
            subject: "Two factor authentication",
            message: mail_template
        }),
        headers: {
            "Content-Type": "application/json"
        }
    });
}

//--------PASSWORD RECOVERY--------VALIDATE CODE
export async function passwordRecoveryValidateCode(req, res) {
    const { email, trace_id, auth_code } = req.body;

    Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

    if (email && trace_id && auth_code) {
        if (isValidEmail(email)) {
            const check_email = await Bucket.data.getAll(`${USER_AUTHENTICATION_BUCKET_ID}`, {
                queryParams: {
                    filter: {
                        email: email
                    }
                }
            });

            if (check_email.length > 0) {
                const auth_code_array = await Bucket.data.getAll(
                    `${PASSWORD_RECOVERY_AUTH_CODE_BUCKET_ID}`,
                    {
                        queryParams: {
                            filter: {
                                trace_id: trace_id
                            }
                        }
                    }
                );
                if (auth_code_array.length > 0) {
                    if (email == auth_code_array[0].email) {
                        if (auth_code_array[0].code == auth_code) {
                            res.status(200).send({
                                message: "Email validated successfully. Write the new password.",
                                message_type: "success"
                            });
                        }
                        //auth code is wrong
                        else {
                            res.status(400).send({
                                message: "Wrong authentication code.",
                                error_type: "wrong_code"
                            });
                        }
                    }
                    //changed email
                    else {
                        res.status(400).send({
                            message: "Wrong email.",
                            error_type: "wrong_email"
                        });
                    }
                }
                //wrong trace id
                else {
                    res.status(400).send({
                        message: "Wrong trace ID.",
                        error_type: "wrong_trace_id"
                    });
                }
            }
            //if there is not any email in the system
            else {
                res.status(400).send({
                    message: "There is not any account with this email.",
                    error_type: "unknown_email"
                });
            }
        } else {
            res.status(400).send({
                message: "Invalid Email address.",
                error_type: "login_failed"
            });
        }
    }
    // undefined email or fullname or password
    else {
        res.status(400).send({
            message: "Please fill all the required inputs.",
            error_type: "required_field"
        });
    }
}

//--------PASSWORD RECOVERY--------CHANGE PASSWORD
export async function passwordRecoveryChangePassword(req, res) {
    const { email, trace_id, auth_code } = req.body;
    const password = await decode(req.body.password);

    Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

    if (email && trace_id && auth_code && password) {
        if (isValidEmail(email)) {
            if (isValidPassword(req.body.password)) {
                const check_email = await Bucket.data.getAll(`${USER_AUTHENTICATION_BUCKET_ID}`, {
                    queryParams: {
                        filter: {
                            email: email
                        }
                    }
                });

                if (check_email.length > 0) {
                    const auth_code_array = await Bucket.data.getAll(
                        `${PASSWORD_RECOVERY_AUTH_CODE_BUCKET_ID}`,
                        {
                            queryParams: {
                                filter: {
                                    trace_id: trace_id
                                }
                            }
                        }
                    );

                    if (auth_code_array.length > 0) {
                        if (email == auth_code_array[0].email) {
                            if (auth_code_array[0].code == auth_code) {
                                //change password

                                let user = check_email[0];
                                // await bcrypt.hash(password, 10)
                                user.password = await bcrypt.hash(password, 10);

                                await Bucket.data
                                    .update(`${USER_AUTHENTICATION_BUCKET_ID}`, user._id, user)
                                    .then(() => {
                                        res.status(200).send({
                                            message: "Great! Your password updated.",
                                            message_type: "success"
                                        });
                                    })
                                    .catch(error => {
                                        console.log(
                                            error,
                                            trace_id,
                                            email,
                                            " Couldn`t update a password."
                                        );
                                        res.status(400).send({
                                            message:
                                                "We couldn`t complete the process. Please try few minutes later again. You can contact us and provide the trace ID: " +
                                                trace_id,
                                            error_type: "unknown_error"
                                        });
                                    });
                            }
                            //auth code is wrong
                            else {
                                res.status(400).send({
                                    message: "E-mail validation failed.",
                                    error_type: "wrong_code"
                                });
                            }
                        }
                        //changed email
                        else {
                            res.status(400).send({
                                message: "Wrong email.",
                                error_type: "wrong_email"
                            });
                        }
                    }
                    //wrong trace id
                    else {
                        res.status(400).send({
                            message: "Wrong trace_id.",
                            error_type: "wrong_trace_id"
                        });
                    }
                }
                //if there is not any email in the system
                else {
                    res.status(400).send({
                        message: "There is not any account with this email.",
                        error_type: "unknown_email"
                    });
                }
            }
            // undefined email or trace_id or auth_code or password
            else {
                res.status(400).send({
                    message: "Please fill all the required inputs.",
                    error_type: "required_field"
                });
            }
        } else {
            res.status(400).send({
                message: "Password must be at least 6 characters.",
                error_type: "login_failed"
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid Email address.",
            error_type: "login_failed"
        });
    }
}

//--------HELPER FUNCTIONS--------

//encode data
function encode(data) {
    return btoa(data);
}

//decode data
function decode(data) {
    return Buffer.from(data, "base64").toString();

    //return window.atob(data);
}

//is email is valid email address
function isValidEmail(email) {
    var mailformat = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;

    if (mailformat.test(String(email).toLowerCase())) {
        return true;
    } else {
        return false;
    }
}

//is password is valid
function isValidPassword(password) {
    if (password.length > 5) {
        return true;
    } else {
        return false;
    }
}

//is fullname is valid
function isValidFullname(fullname) {
    if (fullname.length > 0) {
        return true;
    } else {
        return false;
    }
}

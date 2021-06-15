import * as Bucket from "@spica-devkit/bucket";
const jwt = require("jsonwebtoken");
var bcrypt = require("@node-rs/bcrypt");

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;
const SECRET_API_KEY = process.env.SECRET_API_KEY;
const USER_BUCKET_ID = process.env.USER_BUCKET_ID;
const CONNECTION_BUCKET_ID = process.env.CONNECTION_BUCKET_ID;
const FAVORITES_BUCKET_ID = process.env.FAVORITES_BUCKET_ID;
const CONFIGURATION_BUCKET_ID = process.env.CONFIGURATION_BUCKET_ID;
const USER_AUTHENTICATION_BUCKET_ID = process.env.USER_AUTHENTICATION_BUCKET_ID;

export async function checkUsername(req, res) {
    const { username } = req.body;
    const token = req.headers.get("x-authorization");

    if (tokenChecker(token)) {
        Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

        const user = await Bucket.data.getAll(`${USER_BUCKET_ID}`, {
            queryParams: {
                filter: {
                    username: username
                }
            }
        });

        const forbidden_usernames = await Bucket.data.getAll(`${CONFIGURATION_BUCKET_ID}`, {
            queryParams: {
                filter: {
                    key: "forbidden_usernames"
                }
            }
        });

        if (user.length > 0) {
            res.status(200).send(false);
        } else if (checkUsernameIsForbidden(forbidden_usernames[0].value_array, username)) {
            res.status(200).send(false);
        } else {
            res.status(200).send(true);
        }
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

export async function postUsername(req, res) {
    const { username } = req.body;
    const token = req.headers.get("x-authorization");

    if (tokenChecker(token)) {
        Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

        const user_id = getUserIdFromToken(token);

        const user_array = await Bucket.data.getAll(`${USER_BUCKET_ID}`, {
            queryParams: {
                filter: {
                    _id: user_id
                }
            }
        });

        if (user_array.length > 0) {
            const user = user_array[0];
            user.username = username;

            await Bucket.data
                .update(`${USER_BUCKET_ID}`, user._id, user)
                .then(() => {
                    res.status(200).send({
                        message: "Great! Your username updated.",
                        message_type: "success"
                    });
                })
                .catch(error => {
                    res.status(400).send({
                        message: "Error while updating username."
                    });
                });
        } else {
            res.status(400).send({
                message: "There is not any user with this token."
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

export async function addNewConnection(req, res) {
    const { social_media_id, link } = req.body;
    const token = req.headers.get("x-authorization");

    if (tokenChecker(token)) {
        Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

        const user_id = getUserIdFromToken(token);

        const user_array = await Bucket.data.getAll(`${USER_BUCKET_ID}`, {
            queryParams: {
                filter: {
                    _id: user_id
                }
            }
        });

        if (user_array.length > 0) {
            const user = user_array[0];
            const user_id = user._id;

            await Bucket.data
                .insert(`${CONNECTION_BUCKET_ID}`, {
                    user: `${user_id}`,
                    social_media: `${social_media_id}`,
                    link: `${link}`,
                    status: false
                })
                .then(data => {
                    res.status(200).send({
                        message: "Great! Your added new connection.",
                        message_type: "success"
                    });
                })
                .catch(error => {
                    res.status(400).send({
                        message: "Operation error. Can`t add new connection.",
                        message_type: "error"
                    });
                });
        } else {
            res.status(400).send({
                message: "There is not any user with this token."
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

export async function editConnection(req, res) {
    const { connection_id, link } = req.body;
    const token = req.headers.get("x-authorization");

    if (tokenChecker(token)) {
        Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

        const user_id = getUserIdFromToken(token);

        const connection_array = await Bucket.data.getAll(`${CONNECTION_BUCKET_ID}`, {
            queryParams: {
                filter: {
                    _id: connection_id
                }
            }
        });

        if (connection_array.length > 0) {
            const connection = connection_array[0];
            if (connection.user == user_id) {
                connection.link = link;

                await Bucket.data
                    .update(`${CONNECTION_BUCKET_ID}`, connection._id, connection)
                    .then(data => {
                        res.status(200).send({
                            message: "Connection successfully updated.",
                            message_type: "success"
                        });
                    })
                    .catch(error => {
                        res.status(400).send({
                            message: "can not update connection.",
                            error_type: error
                        });
                    });
            } else {
                res.status(400).send({
                    message: "Invalid user of connection."
                });
            }
        } else {
            res.status(400).send({
                message: "Unknown connection."
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

export async function deleteConnection(req, res) {
    const { connection_id } = req.body;

    const token = req.headers.get("x-authorization");

    if (tokenChecker(token)) {
        Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

        const user_id = getUserIdFromToken(token);

        const connection_array = await Bucket.data.getAll(`${CONNECTION_BUCKET_ID}`, {
            queryParams: {
                filter: {
                    _id: connection_id
                }
            }
        });

        if (connection_array.length > 0) {
            const connection = connection_array[0];

            if (connection.user == user_id) {
                await Bucket.data
                    .remove(`${CONNECTION_BUCKET_ID}`, connection._id)
                    .then(data => {
                        res.status(200).send({
                            message: "Connection successfully deleted.",
                            message_type: "success"
                        });
                    })
                    .catch(error => {
                        res.status(400).send({
                            message: "can not delete connection.",
                            error_type: error
                        });
                    });
            } else {
                res.status(400).send({
                    message: "Invalid user of connection."
                });
            }
        } else {
            res.status(400).send({
                message: "Unknown connection."
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

export async function updateUser(req, res) {
    const { user } = req.body;

    const token = req.headers.get("x-authorization");

    if (tokenChecker(token)) {
        Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

        const user_id = getUserIdFromToken(token);

        const user_array = await Bucket.data.getAll(`${USER_BUCKET_ID}`, {
            queryParams: {
                filter: {
                    _id: user._id
                }
            }
        });

        if (user_array.length > 0) {
            const _user = user_array[0];

            if (user._id == _user._id) {
                _user.fullname = user.fullname;
                _user.country = user.country;
                _user.city = user.city;
                _user.job = user.job;
                await Bucket.data
                    .update(`${USER_BUCKET_ID}`, _user._id, _user)
                    .then(data => {
                        res.status(200).send({
                            message: "User successfully updated.",
                            message_type: "success"
                        });
                    })
                    .catch(error => {
                        res.status(400).send({
                            message: "can not update user.",
                            error_type: error
                        });
                    });
            } else {
                res.status(400).send({
                    message: "Invalid operation."
                });
            }
        } else {
            res.status(400).send({
                message: "Unknown user."
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

export async function deleteUser(req, res) {
    const { user_id } = req.body;

    const token = req.headers.get("x-authorization");
    const user_id_from_token = getUserIdFromToken(token);

    if (tokenChecker(token)) {
        if (user_id == user_id_from_token) {
            //can delete user

            res.status(200).send({
                message: "User successfully deleted.",
                message_type: "success"
            });
        } else {
            res.status(400).send({
                message: "Invalid operation."
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

export async function addToFavorites(req, res) {
    const { user_id, favorite_user_id } = req.body;

    const token = req.headers.get("x-authorization");

    if (tokenChecker(token)) {
        Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

        const user_id_from_token = getUserIdFromToken(token);

        if (user_id != favorite_user_id) {
            if (user_id_from_token == user_id) {
                //get user
                const user_array = await Bucket.data.getAll(`${USER_BUCKET_ID}`, {
                    queryParams: {
                        filter: {
                            _id: user_id
                        }
                    }
                });

                //get favorite user
                const favorite_user_array = await Bucket.data.getAll(`${USER_BUCKET_ID}`, {
                    queryParams: {
                        filter: {
                            _id: favorite_user_id
                        }
                    }
                });

                if (user_array.length > 0 && favorite_user_array.length > 0) {
                    //check already in list or not
                    const favorite_check_array = await Bucket.data.getAll(
                        `${FAVORITES_BUCKET_ID}`,
                        {
                            queryParams: {
                                filter: {
                                    user: user_id,
                                    favorite_user: favorite_user_id
                                }
                            }
                        }
                    );

                    if (!(favorite_check_array.length > 0)) {
                        //add to favorites
                        await Bucket.data
                            .insert(`${FAVORITES_BUCKET_ID}`, {
                                user: user_id,
                                favorite_user: favorite_user_id
                            })
                            .then(data => {
                                res.status(200).send({
                                    message: "Great! You added the user to your favorite list.",
                                    message_type: "success"
                                });
                            })
                            .catch(error => {
                                res.status(400).send({
                                    message: "Operation error. Can`t add to favorite list.",
                                    message_type: "error"
                                });
                            });
                    } else {
                        res.status(400).send({
                            message: "User already in the favorite list."
                        });
                    }
                } else {
                    res.status(400).send({
                        message: "Invalid user."
                    });
                }
            } else {
                res.status(400).send({
                    message: "Invalid operation."
                });
            }
        } else {
            res.status(400).send({
                message: "Invalid operation."
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

export async function deleteFromFavorites(req, res) {
    const { user_id, favorite_user_id } = req.body;
    const token = req.headers.get("x-authorization");

    if (tokenChecker(token)) {
        Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

        const user_id_from_token = getUserIdFromToken(token);

        if (user_id != favorite_user_id) {
            if (user_id_from_token == user_id) {
                //get user
                const user_array = await Bucket.data.getAll(`${USER_BUCKET_ID}`, {
                    queryParams: {
                        filter: {
                            _id: user_id
                        }
                    }
                });

                //get favorite user
                const favorite_user_array = await Bucket.data.getAll(`${USER_BUCKET_ID}`, {
                    queryParams: {
                        filter: {
                            _id: favorite_user_id
                        }
                    }
                });

                if (user_array.length > 0 && favorite_user_array.length > 0) {
                    //check already in list or not
                    const favorite_check_array = await Bucket.data.getAll(
                        `${FAVORITES_BUCKET_ID}`,
                        {
                            queryParams: {
                                filter: {
                                    user: user_id,
                                    favorite_user: favorite_user_id
                                }
                            }
                        }
                    );

                    if (favorite_check_array.length > 0) {
                        //delete from favorites
                        await Bucket.data
                            .remove(`${FAVORITES_BUCKET_ID}`, favorite_check_array[0]._id)
                            .then(data => {
                                res.status(200).send({
                                    message: "Great! You removed the user from your favorite list.",
                                    message_type: "success"
                                });
                            })
                            .catch(error => {
                                res.status(400).send({
                                    message: "Operation error. Can`t remove from favorite list.",
                                    message_type: "error"
                                });
                            });
                    } else {
                        res.status(400).send({
                            message: "User already in the favorite list."
                        });
                    }
                } else {
                    res.status(400).send({
                        message: "Invalid user."
                    });
                }
            } else {
                res.status(400).send({
                    message: "Invalid operation."
                });
            }
        } else {
            res.status(400).send({
                message: "Invalid operation."
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

export async function checkFavoriteRelation(req, res) {
    const { user_id, favorite_user_id } = req.body;

    const token = req.headers.get("x-authorization");

    if (tokenChecker(token)) {
        Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

        const user_id_from_token = getUserIdFromToken(token);

        if (user_id != favorite_user_id) {
            if (user_id_from_token == user_id) {
                const favorite = await Bucket.data.getAll(`${FAVORITES_BUCKET_ID}`, {
                    queryParams: {
                        filter: {
                            user: user_id,
                            favorite_user: favorite_user_id
                        }
                    }
                });

                if (favorite.length > 0) {
                    res.status(200).send(true);
                } else {
                    res.status(200).send(false);
                }
            } else {
                res.status(400).send({
                    message: "Invalid operation."
                });
            }
        } else {
            res.status(400).send({
                message: "Invalid operation."
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

export async function uploadPhoto(req, res) {
    const { url, is_profile_photo } = req.body;

    const token = req.headers.get("x-authorization");

    if (tokenChecker(token)) {
        Bucket.initialize({ apikey: `${SECRET_API_KEY}` });
        const user_id = getUserIdFromToken(token);

        const user_array = await Bucket.data.getAll(`${USER_BUCKET_ID}`, {
            queryParams: {
                filter: {
                    _id: user_id
                }
            }
        });

        if (user_array.length > 0) {
            let user = user_array[0];

            if (is_profile_photo == true) {
                user.profile_photo = url;
            } else if (is_profile_photo == false) {
                user.background_photo = url;
            }

            await Bucket.data
                .update(`${USER_BUCKET_ID}`, user._id, user)
                .then(() => {
                    res.status(200).send({
                        message: "Great! Photo updated.",
                        message_type: "success"
                    });
                })
                .catch(error => {
                    res.status(400).send({
                        message: "Error while updating photo."
                    });
                });
        } else {
            res.status(400).send({
                message: "There is not any user with this token."
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

export async function getFavorites(req, res) {
    const token = req.headers.get("x-authorization");

    if (tokenChecker(token)) {
        Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

        const user_id = getUserIdFromToken(token);

        await Bucket.data
            .getAll(`${FAVORITES_BUCKET_ID}`, {
                queryParams: {
                    relation: true,
                    filter: {
                        user: user_id
                    }
                }
            })
            .then(data => {
                res.status(200).send(data);
            })
            .catch(error => {
                res.status(400).send({ message: "Error while fetching data" });
            });
    } else {
        res.status(400).send({
            message: "Invalid or Expired token detected."
        });
    }
}

//--------UPDATE PASSWORD--------
export async function updatePassword(req, res) {
    console.log(req.body);
    let { passwords } = req.body;

    const token = req.headers.get("x-authorization");

    if (
        passwords &&
        passwords.previous_password &&
        passwords.new_password &&
        passwords.confirmed_password
    ) {
        if (tokenChecker(token)) {
            passwords = {
                previous_password: decode(passwords.previous_password),
                new_password: decode(passwords.new_password),
                confirmed_password: decode(passwords.confirmed_password)
            };

            Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

            if (
                passwords.previous_password != passwords.new_password ||
                passwords.previous_password != passwords.confirmed_password
            ) {
                if (passwords.new_password === passwords.confirmed_password) {
                    const user_id = getUserIdFromToken(token);

                    const user = await Bucket.data
                        .getAll(`${USER_BUCKET_ID}`, {
                            queryParams: {
                                filter: {
                                    _id: user_id
                                }
                            }
                        })
                        .then(data => data[0]);
                    console.log("user: ", user);

                    if (user) {
                        let user_auth = await Bucket.data
                            .getAll(`${USER_AUTHENTICATION_BUCKET_ID}`, {
                                queryParams: {
                                    filter: {
                                        user: user_id
                                    }
                                }
                            })
                            .then(data => data[0]);

                        console.log("user_auth: ", user_auth);

                        if (user_auth) {
                            console.log(passwords.previous_password, user_auth.password);

                            var passwordMatches = await bcrypt.verify(
                                passwords.previous_password,
                                user_auth.password
                            );

                            if (passwordMatches === true) {
                                if (validatePassword(passwords.new_password)) {
                                    // update password

                                    user_auth.password = await bcrypt.hash(
                                        passwords.new_password,
                                        10
                                    );

                                    await Bucket.data
                                        .update(
                                            `${USER_AUTHENTICATION_BUCKET_ID}`,
                                            user_auth._id,
                                            user_auth
                                        )
                                        .then(data => {
                                            res.status(200).send({
                                                message: "Great! Your password updated.",
                                                message_type: "success"
                                            });
                                        })
                                        .catch(error => {
                                            console.log("Error while updating password", error);
                                            res.status(400).send({
                                                message: "Error while updating password.",
                                                error_type: "unknown_error"
                                            });
                                        });
                                } else {
                                    res.status(400).send({
                                        message: "Password must be at least 6 characters.",
                                        error_type: "wrong_password"
                                    });
                                }
                            } else {
                                res.status(400).send({
                                    message: "Previous password is wrong.",
                                    error_type: "wrong_password"
                                });
                            }
                        } else {
                            res.status(400).send({
                                message: "Unknown user."
                            });
                        }
                    } else {
                        res.status(400).send({
                            message: "Unknown user."
                        });
                    }
                } else {
                    res.status(400).send({
                        message: "Passwords are not same.",
                        error_type: "confirm_and_new_password_equality"
                    });
                }
            } else {
                res.status(400).send({
                    message: "New password cannot be same with previous password.",
                    error_type: "previous_and_new_password_equality"
                });
            }
        } else {
            res.status(400).send({
                message: "Invalid or Expired token detected."
            });
        }
    } else {
        res.status(400).send({
            message: "Invalid data type."
        });
    }
}

//check token is valid or not
function tokenChecker(token) {
    if (token) {
        try {
            jwt.verify(token, `${JWT_SECRET_KEY}`);
            return true;
        } catch (error) {
            return false;
        }
    } else {
        return false;
    }
}

//encode data
function encode(data) {
    return btoa(data);
}

//decode data
function decode(data) {
    return Buffer.from(data, "base64").toString();

    //return window.atob(data);
}

function getUserIdFromToken(token) {
    const { header } = jwt.decode(token, { complete: true });
    if (header) {
        return header._id;
    } else {
        return "";
    }
}

function checkUsernameIsForbidden(forbidden_usernames, username) {
    let is_forbidden = false;

    forbidden_usernames.forEach(forbidden_username => {
        if (forbidden_username == username) {
            is_forbidden = true;
        }
    });

    return is_forbidden;
}

function validatePassword(password) {
    if (password.length > 5) {
        return true;
    } else {
        return false;
    }
}

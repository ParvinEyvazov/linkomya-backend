import * as Bucket from "@spica-devkit/bucket";
const jwt = require("jsonwebtoken");

const JWT_SECRET_KEY = process.env.JWT_SECRET_KEY;
const SECRET_API_KEY = process.env.SECRET_API_KEY;
const USER_BUCKET_ID = process.env.USER_BUCKET_ID;
const FAVORITES_BUCKET_ID = process.env.FAVORITES_BUCKET_ID;

export async function search(req, res) {
    Bucket.initialize({ apikey: `${SECRET_API_KEY}` });

    let max_limit;
    const { search_text } = req.query;
    max_limit = req.query.max_limit ? req.query.max_limit : 5;
    let known_user = false;
    let user_id;

    if (req.headers.get("x-authorization")) {
        const token = req.headers.get("x-authorization");
        if (tokenChecker(token)) {
            known_user = true;
            user_id = getUserIdFromToken(token);
        } else {
            res.status(400).send({
                message: "Invalid or Expired token detected."
            });
        }
    }

    let users = known_user ? await loggedIn(user_id, search_text) : await anonim(search_text);

    let sliced_data = arrangeSize(users, max_limit);

    res.status(200).send({ users: sliced_data, can_be_more: users.length > max_limit });
}

async function loggedIn(user_id, search_text) {
    let user_with_same_username_fullname = await getWithUsernameAndFullname(search_text);
    let favorite_user = await getFavorites(user_id, search_text);

    let latest_data = mixData(user_with_same_username_fullname, favorite_user);

    return latest_data;
}

async function anonim(search_text) {
    let user_with_same_username_fullname = await getWithUsernameAndFullname(search_text);

    return user_with_same_username_fullname;
}

async function getWithUsernameAndFullname(search_text) {
    let users = await Bucket.data.getAll(`${USER_BUCKET_ID}`, {
        queryParams: {
            filter: {
                $or: [
                    { fullname: { $regex: `${search_text}`, $options: "si" } },
                    { username: { $regex: `${search_text}`, $options: "si" } }
                ]
            }
        }
    });
    users = filterWithSignificantUsername(users);

    return users;
}

function filterWithSignificantUsername(users) {
    let result = users.filter(user => user.username != undefined);
    return result;
}

async function getFavorites(user_id, search_text) {
    //clean spaces
    // search_text = search_text.replace(/\s/g, "");
    // let letter_filter = createLetterFilter(search_text);

    let users = await Bucket.data.getAll(`${FAVORITES_BUCKET_ID}`, {
        queryParams: {
            filter: {
                user: user_id
            },
            relation: "favorite_user"
        }
    });

    let modified_data = eliminateFavoriteData(users);

    return modified_data;
}

function createLetterFilter(search_text) {
    let filter = [];

    for (let c of search_text) {
        filter.push(
            { "favorite_user.fullname": { $regex: `${c}`, $options: "si" } },
            { "favorite_user.username": { $regex: `${c}`, $options: "si" } }
        );
    }

    return filter;
}

function eliminateFavoriteData(favorite_users) {
    favorite_users.forEach(function(element, index, array) {
        array[index] = element.favorite_user;
    });

    return favorite_users;
}

function mixData(user_with_same_username_fullname, favorite_user) {
    let mixed_data = [];

    user_with_same_username_fullname.forEach(element1 => {
        favorite_user.forEach(element2 => {
            if (element1._id == element2._id) {
                mixed_data.push(element1);
            }
        });
    });

    mixed_data.forEach(m => {
        var index1 = user_with_same_username_fullname
            .map(function(item) {
                return item._id;
            })
            .indexOf(m._id);

        if (index1 != -1) user_with_same_username_fullname.splice(index1, 1);

        var index2 = favorite_user
            .map(function(item) {
                return item._id;
            })
            .indexOf(m._id);

        if (index2 != -1) favorite_user.splice(index2, 1);

        //deyisdirildi - TEST IT
        /*
        var index1 = user_with_same_username_fullname
            .map(function(item) {
                return item._id;
            })
            .indexOf(m._id);

        var index2 = favorite_user
            .map(function(item) {
                return item._id;
            })
            .indexOf(m._id);


        user_with_same_username_fullname.splice(index1, 1);
        favorite_user.splice(index2, 1);
         */
    });

    var latest_data = mixed_data.concat(user_with_same_username_fullname, favorite_user);

    return latest_data;
}

function arrangeSize(users, max_limit) {
    let sliced_data = users.slice(0, max_limit);
    return sliced_data;
}

//----- helper function -----
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

function getUserIdFromToken(token) {
    const { header } = jwt.decode(token, { complete: true });
    if (header) {
        return header._id;
    } else {
        return "";
    }
}

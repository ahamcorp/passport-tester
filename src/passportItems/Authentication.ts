//contains functions related to authentication
    //tokens
    //passport validation

const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const SECRET = 'passport-test';

const validatePassword = (password, storedHash, storedSalt) => {
    //query LoginInfo table and check if the hashed version of the input password is the same as the one stored
    //i guess i'll also need the username?
    // const storedSalt = ""
    // const storedHash = ""
    const thisHash = crypto.pbkdf2Sync(password, storedSalt, 10000, 64, 'sha512').toString('hex');
    return storedHash === thisHash;
}

const generateJWT = (username, id) => {
    const today = new Date();
    const expirationDate = new Date(today);
    expirationDate.setDate(today.getDate() + 60);

    return jwt.sign({
        username: username,
        id: id,
        exp: (expirationDate.getTime() / 1000)
    }, SECRET);
};

const verifyToken = (token, done) => {
    jwt.verify(token, SECRET, (err, decoded) => {
        if (err){
            done(null, false, {message: "invalid cookie token"});
        }
        console.log('this is the decoded item ', decoded);
        done(null, decoded);
    });
};

//this function isn't very useful. because expiration date of a cookie needs to be front and center
    //but this function encrypts the expiration date
const generateExpiredToken = () => {

    const expiredDate = new Date('December 2, 1990 03:24:00');
    return jwt.sign({
        exp: (expiredDate.getTime() / 1000)
    }, SECRET);

}

const toAuthJSON = (username, id) => {
    return {
        username: username,
        id: id,
        token: generateJWT(username, id)
    }
};

export {SECRET, validatePassword, generateJWT, generateExpiredToken, toAuthJSON, verifyToken};
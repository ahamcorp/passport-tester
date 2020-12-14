//don't pay attention to this auth. this one is just random stuff taken from another guide. Auth is the better one.

const jwt = require('express-jwt');

const getTokenFromHeaders = (req) => {
    const {authorization} = req.headers;
    console.log('calling getTokenFromHeaders');
    if ( authorization && authorization.split(' ')[0] === 'Token' ){
        return authorization.split(' ')[1];
    }
    return null;
}


const auth = {
    required: jwt({
        secret: 'secret',
        userProperty: 'payload',
        getToken: getTokenFromHeaders,
        algorithms: ['RS256']
    }),
    optional: jwt({
        secret: 'secret',
        userProperty: 'payload',
        getToken: getTokenFromHeaders,
        credentialsRequired: false,
        algorithms: ['RS256']
    })
};

export default auth;
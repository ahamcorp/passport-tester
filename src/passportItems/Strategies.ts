const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const passportJWT = require('passport-jwt')
const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;

const passportCookie = require('passport-cookie');
const CookieStrategy = passportCookie.Strategy;

import {LoginInfo} from "../entity/LoginInfo";
import {SECRET, validatePassword, verifyToken} from "./Authentication";

export default function passportSetup(connection) {

    passport.serializeUser((username, done) => {
        done(null, username);
    });
    
    
    passport.deserializeUser(async (username, done) => {
        console.log('username is ', username);
        let loginInfo = await connection
                                .getRepository(LoginInfo)
                                .createQueryBuilder("login")
                                .where("login.username = :username", {username: username})
                                .getOne();
        if (!loginInfo ){
            return done('unauthorized', false, "no login info");
        }
        return done(null, {username: username, userid: loginInfo.userID}) 
    })
    
    
    passport.use(new LocalStrategy(
        async (username, password, done) => {
            //done is a function. the second parameter should be the object you wanted
            let loginInfo = await connection
                                        .getRepository(LoginInfo)
                                        .createQueryBuilder("login")
                                        .where("login.username = :username", {username: username})
                                        .getOne();
            console.log('huh? ', loginInfo);
            if (!loginInfo || !validatePassword(password, loginInfo.hash, loginInfo.salt)){
                console.log('this be invalid');
                return done(null, false, {errors: {'username or password': 'is invalid'}});
            }
            return done(null, {username: username, userid: loginInfo.userID}) 
        }
    ));
    
    passport.use(new JWTStrategy({
            jwtFromRequest: ExtractJWT.fromAuthHeaderAsBearerToken(),
            secretOrKey: SECRET
        },
        async (jwtPayload, callback) => {
            console.log('this is the jwtPayload ', jwtPayload);
            const {username, userid} = jwtPayload;
            //this is where you can verify if the username/id is in the db or not
            let loginInfo = await connection
                                .getRepository(LoginInfo)
                                .createQueryBuilder("login")
                                .where("login.username = :username", {username: username})
                                .getOne();
            if (!loginInfo){
                return callback(null, false, {message: 'invalid token'});
            }
            return callback(null, jwtPayload);
        }
    ));
    
    
    passport.use(new CookieStrategy({
        cookieName: 'token'
    }, (token, done) => {
        console.log('now starting cookie strategy');
        verifyToken(token, done);
        done(null, false, {message: "invalid cookie token"});
    
    }));


    return passport;

}


import "reflect-metadata";
import {createConnection} from "typeorm";
import * as express from "express";
import * as bodyParser from "body-parser";
const cors = require('cors');
const expressSession = require('express-session');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const cookieParser = require('cookie-parser');

const passportSetup = require('./passportItems/Strategies').default;
console.log(passportSetup);

import {Request, Response} from "express";
import {Routes} from "./routes";
import {User} from "./entity/User";
import {LoginInfo} from "./entity/LoginInfo";
import auth from './passportItems/auth';
import { Stats } from "fs";
import { STATUS_CODES } from "http";
import {SECRET, generateJWT, toAuthJSON} from './passportItems/Authentication';

createConnection().then(async connection => {

    // create express app
    const app = express();
    app.use(cookieParser());
    app.use(bodyParser.json());

    const corsConfig = {
        credentials: true,
        // origin: "http://localhost:8080"
        origin: true
        // origin: "localhost:8080",
    };

    app.use(cors(corsConfig));

    //middleware for generating session cookies and matching them with data stored server side eg. logged in user
    app.use(expressSession({
        secret: SECRET, 
        cookie: { maxAge: 6000 }, 
        resave: false, 
        saveUninitialized: false 
    }));
    
    const passport = passportSetup(connection);
    app.use(passport.initialize());
    app.use(passport.session());


    // register express routes from defined application routes
    Routes.forEach(route => {
        (app as any)[route.method](route.route, (req: Request, res: Response, next: Function) => {
            const result = (new (route.controller as any))[route.action](req, res, next);
            if (result instanceof Promise) {
                result.then(result => result !== null && result !== undefined ? res.send(result) : undefined);

            } else if (result !== null && result !== undefined) {
                res.json(result);
            }
        });
    });

    app.get('/', (req, res) => {
        return res.send('yop');
    });

    app.get('/logout', (req, res) => {
        // res.cookie('token', generateExpiredToken(), {httpOnly: false});
                    // res.append('Set-Cookie', 'token=' + token + ';');
        res.cookie('token', '', {httpOnly: false, maxAge: 0});
        return res.json({message: 'Successfully logged out'});
    });

        //this should be called for signup
    app.post('/user', async (req, res) => {
        const {username, password} = req.body;

        let userRegistered = await connection
                                    .getRepository(LoginInfo)
                                    .createQueryBuilder("login")
                                    .where("login.username = :username", {username: username})
                                    .getOne();
        if (userRegistered){
            //if the user exists, send an object with a token over
            return res.send(toAuthJSON(username, userRegistered.userID));
            // return res.send('user is already registered');
        }

        //if there's a user but not hashed password, then it sets it
        let user: any = await connection
                            .getRepository(User)
                            .createQueryBuilder("user")
                            .where("user.username = :username", {username: username})
                            .getOne();

        if (user===undefined){
            let newUser = new User();
            newUser.username=username;
            user = await connection.manager
                        .save(newUser)
                        .then(newUser => {
                            console.log('the user info is ', newUser);
                            return newUser;
                        })
                        .catch(err => console.log(err));
            console.log(user, typeof user)
        }

        console.log('the user info is ', user);

        const salt = crypto.randomBytes(16).toString('hex');
        const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');

        let loginInfo = new LoginInfo();
        loginInfo.username = username;
        loginInfo.userID = user.userID;
        loginInfo.salt = salt;
        loginInfo.hash = hash;

        const loginResult = await connection.manager
                                .save(loginInfo)
                                .then(loginInfo => {
                                    console.log('the log in info is ', loginInfo)
                                    return loginInfo
                                })
                                .catch(err => console.log(err));
        
        if (loginResult){
            const token = generateJWT(user.username, user.userid);
            return res.cookie('token', token, {httpOnly: false});
        } else {
            res.send('login storage failed');
        }

    });

    app.post('/login', (req, res) => {
        console.log('login endpoint queried');
        const {authMethod} = req.body;
        console.log(req.body);
        if (!authMethod){
            return res.status(400).json({
                message: 'Please include authMethod',
                valid: false
            });
        }

        if (authMethod==='local'){
            console.log(req.body.username, req.body.password);
            return passport.authenticate('local', {session: false}, (err, user, info) => {
                console.log('starting the authentication ', user);
                if (err || !user){
                    return res.status(500).json({
                        message: "Something is not right",
                        valid: false,
                        user: user
                    });
                }
                if (user) {
                    console.log('it has gotten inside here ', user);
                    const token = generateJWT(user.username, user.userid);
                    // const authInfo = toAuthJSON(user.username, user.userid); //contains username, userid, and token
                    // res.cookie('authInfo', authInfo, {httpOnly: true});
                    //here's what im thinking. we store the token in the cookie but the other info inside the json response
                    //res.cookie('token', token, {httpOnly: true});
                    console.log('look at this cookie all crisp and ready to be sent ', token);

                    //res.header('Access-Control-Allow-Credentials', true);
                    // res.setHeader('Access-Control-Allow-Origin', 'http://localhost:8080');
                    // res.setHeader('Access-Control-Allow-Credentials', true);
                    // res.setHeader('Access-Control-Allow-Origin', '127.0.0.1:8080');
                    // res.header('Access-Control-Allow-Origin', 'localhost:8080');
                    // res.header('Access-Control-Allow-Credentials', true);
                    // res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
                    
                    // //res.header("Access-Control-Allow-Origin", "*"); //localhost:8080
                    // res.header("Access-Control-Allow-Origin", "localhost:8080");

                    res.cookie('token', token, {httpOnly: false});
                    // res.append('Set-Cookie', 'token=' + token + ';');


                    return res.json({user: {username: user.username, id: user.userid}, valid: true});
                }
                return res.status(400).info;
            })(req, res);
        } else if (authMethod==="cookie"){
            console.log("now attempting cookie validation ", req.cookies);
            console.log(req.cookies.token);
            return passport.authenticate('cookie', { session: false }, (err, payload, info) => {
                //this try catch statement is because there's a weird bug where the callback function sometimes gets called more than once
                try {
                    console.log('the jwt payload inside of cookie body is ', payload);
                    if (err || !payload){
                        return res.status(401).json({
                            valid: false,
                            message: "Something is not right",
                            payload: payload
                        });
                    }
                    return res.send({user: {username: payload.username, id: payload.id}, valid: true});
                } catch(error) {
                    res.status(500).end('error');
                }
            })(req, res);
        }
    });

    //THIS IS THE WORKING VERSION. IM JUST GOING TO UPDATE IT SO THAT THE ORDER IS MORE ORGANIZED
    // app.post('/login', (req, res) => {
    //     //we need to break from this statement if the cookie is invalid. 
    //     if (req.cookies.token){
    //         console.log("now attempting cookie validation");
    //         console.log(req.cookies.token);
    //         return passport.authenticate('cookie', { session: false }, (err, payload, info) => {

    //             try {
    //                 console.log('the jwt payload inside of cookie body is ', payload);
    //                 if (err || !payload){
    //                     return res.status(400).json({
    //                         valid: false,
    //                         message: "Something is not right",
    //                         payload: payload
    //                     });
    //                 }
                    
    //                 return res.send({...payload, valid: true});
    //             } catch(error) {
    //                 res.status(500).end('error');
    //             }
    //         })(req, res);
    //     }

    //     const {authMethod} = req.query;
    //     if (authMethod==="token"){

    //         return passport.authenticate('jwt', {session: false}, (err, jwtPayload, info) => {
    //             if (err || !jwtPayload){
    //                 return res.status(400).json({
    //                     valid: false,
    //                     message: "Something is not right",
    //                     jwtPayload: jwtPayload
    //                 });
    //             }
    //             console.log('the jwt inside of login body is ', jwtPayload);
    //             res.send({...jwtPayload, valid: true});
    //         })(req, res);

    //     } else {
    //         return passport.authenticate('local', {session: false}, (err, user, info) => {
    //             console.log('starting the authentication ', user);
    //             if (err || !user){
    //                 return res.status(400).json({
    //                     message: "Something is not right",
    //                     user: user
    //                 });
    //             }
    //             if (user) {
    //                 console.log('it has gotten inside here ', user);
    //                 const token = generateJWT(user.username, user.userid);
    //                 // const authInfo = toAuthJSON(user.username, user.userid); //contains username, userid, and token
    //                 // res.cookie('authInfo', authInfo, {httpOnly: true});
    //                 //here's what im thinking. we store the token in the cookie but the other info inside the json response
    //                 res.cookie('token', token, {httpOnly: true});

    //                 return res.json({user: {username: user.username, id: user.userid}});
    //             }
    //             return res.status(400).info;
    //         })(req, res);
    //   }
    // });


    // app.post('/login', auth.optional, (req, res, next) => {
    //     console.log('now querying login');
    //     const {username, password} = req.body;

    //     if (!username){
    //         return res.status(422).json({
    //             error: "username not provided"
    //         })
    //     }
    //     if (!password){
    //         return res.status(422).json({
    //             error: "password not provided"
    //         })
    //     }

    //     //this carries out the local strategy that you defined.
    //     return passport.authenticate('local', {session: false}, (err, passportUser, info) => {
    //         if (err) {
    //             return res.send(err);
    //         }
    //         console.log('huh wut? ', passportUser);

    //         if (passportUser) {
    //             console.log('it has gotten inside here ', passportUser);
    //             const user = passportUser;
    //             user.token = generateJWT(passportUser.username, passportUser.userid);

    //             return res.json({user: toAuthJSON(passportUser.username, passportUser.userid)})
    //         }

    //         return res.status(400).info;
    //     })(req, res, next)



    // })

    // setup express app here
    // ...

    // start express server
    app.listen(3003);

    // insert new users for test
    // await connection.manager.save(connection.manager.create(User, {
    //     firstName: "Timber",
    //     lastName: "Saw",
    //     age: 27
    // }));
    // await connection.manager.save(connection.manager.create(User, {
    //     firstName: "Phantom",
    //     lastName: "Assassin",
    //     age: 24
    // }));

    console.log("Express server has started on port 3003. Open http://localhost:3003/users to see results");

}).catch(error => console.log(error));

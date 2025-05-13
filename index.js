require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { database } = require('./databaseConnection');
const path = require('path');

const port = process.env.PORT || 3000;
const expireTime = 60 * 60 * 1000; 

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const app = express();
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

let userCollection;

(async () => {
    await database.connect();
    userCollection = database.db(mongodb_database).collection('users');

    var mongoStore = MongoStore.create({
        mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
        crypto: { secret: mongodb_session_secret }
    });

    app.use(session({
        secret: node_session_secret,
        store: mongoStore,
        saveUninitialized: false,
        resave: true,
        cookie: { maxAge: expireTime }
    }));

    // Middleware to make session variables available in all templates
    app.use((req, res, next) => {
        res.locals.authenticated = !!req.session.name;
        res.locals.name = req.session.name || '';
        res.locals.userType = req.session.userType || '';
        res.locals.email = req.session.email || '';
        next();
    });

    app.get('/', (req, res) => {
        res.render('index', { 
            authenticated: !!req.session.name,
            name: req.session.name,
            userType: req.session.userType
        });
    });

    app.get('/signup', (req, res) => {
        res.render('signup');
    });

    app.post('/signupSubmit', async (req, res) => {
        const schema = Joi.object({
            name: Joi.string().required(),
            email: Joi.string().email().required(),
            password: Joi.string().required()
        });
        const { error } = schema.validate(req.body);
        if (error) {
            return res.render('signup', { 
                error: error.details[0].message
            });
        }
        const { name, email, password } = req.body;
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
            return res.render('signup', {
                error: 'Email already registered.'
            });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        
        await userCollection.insertOne({ 
            name, 
            email, 
            password: hashedPassword,
            userType 
        });
        
        req.session.name = name;
        req.session.email = email;
        req.session.userType = userType;
        
        res.redirect('/members');
    });

    app.get('/login', (req, res) => {
        res.render('login');
    });

    app.post('/loginSubmit', async (req, res) => {
        const schema = Joi.object({
            email: Joi.string().email().required(),
            password: Joi.string().required()
        });
        const { error } = schema.validate(req.body);
        if (error) {
            return res.render('login', {
                error: error.details[0].message
            });
        }
        const { email, password } = req.body;
        const user = await userCollection.findOne({ email });
        if (!user) {
            return res.render('login', {
                error: 'Invalid email/password combination.'
            });
        }
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.render('login', {
                error: 'Invalid email/password combination.'
            });
        }
        req.session.name = user.name;
        req.session.email = user.email;
        req.session.userType = user.userType || 'user'; // Default to user if not set
        
        res.redirect('/members');
    });

    app.get('/members', (req, res) => {
        if (!req.session.name) {
            return res.redirect('/');
        }
        
        res.render('members', {
            name: req.session.name,
            userType: req.session.userType
        });
    });
    
    // Admin page route
    app.get('/admin', async (req, res) => {
        console.log('ADMIN ROUTE HIT', req.session);
        if (!req.session.name) {
            return res.redirect('/login');
        }
        if (req.session.userType !== 'admin') {
            return res.status(403).render('error', {
                message: 'You are not authorized to view this page.',
                status: 403
            });
        }
        const users = await userCollection.find({}).toArray();
        res.render('admin', {
            name: req.session.name,
            userType: req.session.userType,
            users: users,
            currentUserEmail: req.session.email
        });
    });
    
    // Route to promote user to admin
    app.get('/promote', async (req, res) => {
        if (!req.session.name || req.session.userType !== 'admin') {
            return res.status(403).render('error', {
                message: 'You are not authorized to perform this action.',
                status: 403
            });
        }
        
        const { email } = req.query;
        if (!email) {
            return res.redirect('/admin');
        }
        
        await userCollection.updateOne(
            { email: email },
            { $set: { userType: 'admin' } }
        );
        
        res.redirect('/admin');
    });
    
    // Route to demote admin to user
    app.get('/demote', async (req, res) => {
        if (!req.session.name || req.session.userType !== 'admin') {
            return res.status(403).render('error', {
                message: 'You are not authorized to perform this action.',
                status: 403
            });
        }
        
        const { email } = req.query;
        if (!email) {
            return res.redirect('/admin');
        }
        
        await userCollection.updateOne(
            { email: email },
            { $set: { userType: 'user' } }
        );
        
        res.redirect('/admin');
    });

    app.get('/logout', (req, res) => {
        req.session.destroy(() => {
            res.redirect('/');
        });
    });
    
    // Custom 404 handler
    app.use((req, res) => {
        res.status(404).render('404');
    });

    app.get('/test', (req, res) => {
        console.log('TEST ROUTE HIT');
        res.send('Test route hit');
    });

    app.listen(port, () => {
        console.log(`Server is running on http://localhost:${port}`);
    });
})();
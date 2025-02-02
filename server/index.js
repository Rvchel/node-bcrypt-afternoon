//required library
require('dotenv').config();
const express  = require('express');
const massive = require('massive');
const session = require('express-session');
const authCtrl = require('./controllers/authController');
const treasureCtrl = require('./controllers/treasureController');
const auth = require('./middleware/authMiddleware');

const app = express();

//Destructuring port, string & secret.
const SERVER_PORT = 4000;
const {CONNECTION_STRING, SESSION_SECRET} = process.env;

//req.body
app.use(express.json());

//massive (for database)
massive(CONNECTION_STRING).then(db => {
    app.set('db', db);
    console.log('Database Connected');
});

//middleware
app.use(session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
}));

//endpoints
app.post('/auth/register', authCtrl.register);
app.post('/auth/login', authCtrl.login);
app.get('/auth/logout', authCtrl.logout);
app.get('/api/treasure/dragon', treasureCtrl.dragonTreasure);
app.get('/api/treasure/user', auth.usersOnly, treasureCtrl.getUserTreasure);
app.post('/api/treasure/user', auth.usersOnly, treasureCtrl.addUserTreasure);
app.get('/api/treasure/all', auth.adminsOnly, auth.usersOnly, treasureCtrl.getAllTreasure);



//Port
app.listen(SERVER_PORT, () => {
    console.log(`Listening on port ${SERVER_PORT}`);
});
const bcrypt = require('bcryptjs');

async function register(req, res) {
    const {username, password, isAdmin} = req.body;
    const db = req.app.get('db');
    const result = await db.get_user([username]);
    const existingUser = result[0];
    if (existingUser) {
        res.status(409).json({error: 'Username Taken'});
    }
    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);
    const registeredUser = await db.register_user([isAdmin, username, hash]);
    const user = registeredUser[0];
    req.session.user = {
        isAdmin: user.is_admin,
        username: user.username,
        id: user.id
    };
        res.status(201).json(req.session.user);

};




async function login(req, res) {
    const {username, password} = req.body;
    const foundUser = await req.app.get('db').get_user([username]);
    const user = foundUser[0];
    if (!user) {
        res.status(401).json({error:'User not found. Please register as a new user before logging in.' });
    }
    const isAuthenticated = bcrypt.compareSync(password, user.hash);
    if (!isAuthenticated) {
        res.status(403).json({error: 'Incorrect Password.'});
    }
    req.session.user = {isAdmin: user.isAdmin, id: user.is, username: user.username};
    res.status(200).json(req.session.user);

};




async function logout(req, res) {
    req.session.destroy();
    res.sendStatus(200);
};










module.exports = {
    register,
    login,
    logout
}
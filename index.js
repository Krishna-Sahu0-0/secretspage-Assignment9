const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
require('dotenv').config();

const app = express();
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use(cookieParser());

const mongoose = require("mongoose");
mongoose.connect(process.env.MONGO_URI);

const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
});

const User = mongoose.model("User", userSchema);

const JWT_SECRET = process.env.JWT_SECRET || "SuperSecretJWTKey";

// Middleware to protect routes
function authenticateToken(req, res, next) {
    const token = req.cookies.token;
    if (!token) return res.redirect('/login');
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.redirect('/login');
        req.user = user;
        next();
    });
}

app.get("/", function(req, res) {
    res.render("home");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.post("/register", async function (req, res) {
    const { name, email, password } = req.body;

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.render("register", { error: "Invalid email format." });
    }

    // Password format validation: min 6 chars, at least 1 lowercase, 1 uppercase, 1 number
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)[A-Za-z\d!@#$%^&*]{6,}$/;
    if (!passwordRegex.test(password)) {
        return res.render("register", { error: "Password must be at least 6 characters, include lowercase, uppercase, and a number." });
    }

    try {
        const existingUser = await User.findOne({ email: email });
        if (existingUser) {
            // Check if password matches
            const match = await bcrypt.compare(password, existingUser.password);
            if (match) {
                // Log in the user and redirect to secrets with popup
                const token = jwt.sign({ id: existingUser._id, name: existingUser.name, email: existingUser.email }, JWT_SECRET, { expiresIn: '1h' });
                res.cookie('token', token, { httpOnly: true, secure: false });
                // Pass a query param to show the alert
                return res.redirect("/secrets?alreadyRegistered=true");
            } else {
                return res.render("register", { error: "Incorrect password and this email is already registered. Try login with correct password." });
            }
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({
            name,
            email,
            password: hashedPassword
        });
        await newUser.save();
        // Log in the new user and redirect to secrets
        const token = jwt.sign({ id: newUser._id, name: newUser.name, email: newUser.email }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true, secure: false });
        res.redirect("/secrets");
    } catch (err) {
        console.log(err);
        res.status(500).send("An error occurred while registering the user.");
    }
});

app.get("/login", function(req, res) {
    res.render("login");
});

app.post("/login", async function (req, res) {
    const { email, password } = req.body;

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
        return res.render("login", { error: "Invalid email format." });
    }

    try {
        const user = await User.findOne({ email: email });
        if (!user) {
            return res.render("login", { error: "No user found with that email." });
        }
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.render("login", { error: "Incorrect password." });
        }
        // Create JWT token
        const token = jwt.sign({ id: user._id, name: user.name, email: user.email }, JWT_SECRET, { expiresIn: '1h' });
        res.cookie('token', token, { httpOnly: true, secure: false });
        res.redirect("/secrets");
    } catch (err) {
        console.log(err);
        res.status(500).send("An error occurred while logging in.");
    }
});

app.get("/secrets", authenticateToken, function (req, res) {
    const alreadyRegistered = req.query.alreadyRegistered === "true";
    res.render("secrets", { user: req.user, alreadyRegistered });
});

// Logout route
app.get("/logout", function(req, res) {
    res.clearCookie('token');
    res.redirect('/login');
});

app.listen(8000, function() {
    console.log("Server started");
});

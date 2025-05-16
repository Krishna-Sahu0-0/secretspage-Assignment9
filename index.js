const express = require('express');
const bodyParser = require('body-parser');
const encrypt = require('mongoose-encryption');
var app = express();
app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

require('dotenv').config();
const mongoose = require("mongoose");
mongoose.connect(process.env.MONGO_URI);
const trySchema = new mongoose.Schema({
    email: String,
    password: String
});

const secret = "ThisislittleSecret";
trySchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });
const item = mongoose.model("second", trySchema);
app.get("/", function(req, res) {
    res.render("home");
});
app.post("/register", async function (req, res) {
    const email = req.body.username;
    const password = req.body.password;

    const passwordRegex = /^(?=.*[0-9])(?=.*[!@#$%^&*])[A-Za-z0-9!@#$%^&*]{8,}$/;
    if (!passwordRegex.test(password)) {
        return res.send("Password must be at least 8 characters long and include at least one number and one special character.");
    }

    try {
        const existingUser = await item.findOne({ email: email });
        if (existingUser) {
            res.send("You already have an account with this email. Try logging in with the correct password.");
        } else {
            const newUser = new item({
                email: email,
                password: password
            });
            await newUser.save();
            res.render("secrets");
        }
    } catch (err) {
        console.log(err);
        res.status(500).send("An error occurred while registering the user.");
    }
});
app.post("/login", async function (req, res) {
    const username = req.body.username;
    const password = req.body.password;

    try {
        const foundUser = await item.findOne({ email: username });
        if (foundUser) {
            if (foundUser.password === password) {
                res.render("secrets");
            } else {
                res.send("Incorrect password.");
            }
        } else {
            res.send("No user found with that email.");
        }
    } catch (err) {
        console.log(err);
        res.status(500).send("An error occurred while logging in.");
    }
});

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.listen(8000, function() {
    console.log("Server started");
});

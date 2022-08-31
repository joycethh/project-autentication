//require moudles
require("dotenv").config();

const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth2").Strategy;
const findOrCreate = require("mongoose-findorcreate");
const { application } = require("express");
const app = express();
const port = 3000;

//set up view engine and serve static files
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

//initialize middleware by using 'express-session'
app.use(
  session({
    secret: "OurLittleSecret.",
    resave: false,
    saveUninitialized: true,
  })
);

//init passport authentication
app.use(passport.initialize());
//allow passport to use 'express-session'
app.use(passport.session());

//Mongoose connection|Schema |Plugin |Model
main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect("mongodb://localhost:27017/userDB");
}

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String,
});
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);
const User = mongoose.model("User", userSchema);

//passport-local-strategy configuration
passport.use(User.createStrategy());

//passport-google-strategy configuration
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      passReqToCallback: true,
    },
    function (request, accessToken, refreshToken, profile, done) {
      User.findOrCreate({ googleId: profile.id }, function (err, user) {
        return done(err, user);
      });
    }
  )
);

//implement serializeUser & deserializeUser function
passport.serializeUser(function (user, cb) {
  process.nextTick(function () {
    cb(null, { id: user.id, username: user.username });
  });
});

passport.deserializeUser(function (user, cb) {
  process.nextTick(function () {
    return cb(null, user);
  });
});

//render home/login/register page
app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

//Google strategy authentication
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["email", "profile"] })
);
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

//local strategy -  save newUser
app.post("/register", (req, res) => {
  User.register(
    { username: req.body.username },
    req.body.password,
    (err, user) => {
      if (err) {
        console.log("registered failed, try again " + err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, () => {
          res.redirect("/secrets");
        });
      }
    }
  );
});

//local strategy - login & validator
app.post("/login", (req, res) => {
  const user = new User({
    username: req.body.username,
    password: req.body.password,
  });
  req.login(user, (err) => {
    if (err) {
      console.log("login failed " + err);
    } else {
      passport.authenticate("local")(req, res, () => {
        res.redirect("/secrets");
      });
    }
  });
});

//protect logged in routes
app.get("/secrets", function (req, res) {
  User.find({ secret: { $ne: null } }, function (err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    }
  });
});

//submit page
app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});
app.post("/submit", (req, res) => {
  const newContent = req.body.secret;
  User.findById(req.user.id, (err, foundUser) => {
    if (err) {
      console.log("user does not exist " + err);
    } else {
      if (foundUser) {
        foundUser.secret = newContent;
        foundUser.save(() => res.redirect("/secrets"));
      }
    }
  });
});
//clear the sessions object | define log out
app.get("/logout", (req, res) => {
  console.log(req.session.passport);
  req.logout();
  res.redirect("/");
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});

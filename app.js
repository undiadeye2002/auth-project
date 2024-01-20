import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
// To impliment login for a user who is already store on our database. we want to be bale to auth the session started up in passport
import { Strategy } from "passport-local";
import env from "dotenv"


const app = express();
const port = 3000;
const saltRounds = 10;

env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(
  session({
    secret: process.env.PG_SECRET ,
    resave: false,
    saveUninitialized: true,
    // Time for how session will be saved in the browers
    cookie:{//min * sec * hr => to get a day
      maxAge: 1000 * 60 * 60 * 24
    }
  })
)
app.use(passport.initialize())
app.use(passport.session())

const db = new pg.Client({
  user: process.env.PG_USER ,
  host: process.env.PG_HOST ,
  database: process.env.PG_DATABASE ,
  password: process.env.PG_PASSWORD ,
  port: process.env.PG_PORT,
});
db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});
app.get("/logout", (req,res) => {
    req.logout(function(err){
        if(err){
            return next(err)
        }
        res.redirect('/');
    });
})

// This is cookies and session.
app.get('/secrets', (req, res) => {
  // To check if its auth
  console.log(req.user)
  if(req.isAuthenticated()){
    res.render("page.ejs")
  }else{
    res.redirect('/login')
  }
})
// updating our register route using passort
app.post("/register", async (req, res) => {
  const email = req.body.email;
  const username = req.body.username;
  const password = req.body.password;

  try {
    const checkDetails = await db.query("SELECT * FROM marv WHERE username = $1 AND email = $2", [
      username, email,
    ]);

    if (checkDetails.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //hashing the password and saving it in the database
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          console.log("Hashed Password:", hash);
          const result = await db.query(
            "INSERT INTO marv(username, email, password) VALUES ($1, $2, $3) RETURNING *",
            [ username, email, hash]
          );
          // set the new user
          const user = result.rows[0]
          //save the user to the session
          req.login(user, (err) => [
            console.log('SUCCESS'),
            res.redirect("/secrets")
          ]);
        }
      });
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login",passport.authenticate("local", {
  successRedirect: "/secrets",
  failureRedirect: "/login"
}));
// Middlare for passport-local . trying to  vaildate if the user already has the right passsword, all exist in the database 
passport.use(new Strategy(async function verify(username, password, cb){

  try {
    const result = await db.query("SELECT * FROM marv WHERE email = $1", [
      username,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;
      bcrypt.compare(password, storedHashedPassword, (err, valid) => {
        if (err) {
            //Error with password check
            console.log("Error comparing password", err)
          return cb(err)
        } else {
          if (valid) {
            //Passed password check
            return cb(null, user)
          } else {
            //did not pass password check
            return cb(null, false)
          }
        }
      });
    } else {
      return cb('User not found')
    }
  } catch (err) {
    return cb(err)
  }
}))

passport.serializeUser((user, cb) => [
  cb(null, user)
]);
passport.deserializeUser((user, cb) => [
  cb(null, user)
])
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

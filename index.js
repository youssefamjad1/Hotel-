import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true, // Set to false to save uninitialized sessions
    cookie: { maxAge: 10000 } // Max age of the session cookie set to 10 seconds (in milliseconds)
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static('public')); // Serve files from the 'public' directory

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

app.set("view engine", "ejs"); // Set view engine to EJS

app.get("/", (req, res) => {
  res.render("home"); // Render the home page
});

app.get('/book-now', (req, res) => {
  res.render('signinup'); // Render the sign-in/sign-up page
});

app.get("/login", (req, res) => {
  res.redirect("/hotel");
});

app.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

app.get("/hotel", async (req, res) => {
  //console.log(req.isAuthenticated());
  if (req.isAuthenticated()) {
    try {
      // Fetch all hotel information from the database
      const result = await db.query("SELECT * FROM hotels");
      //console.log(result);
      const hotels = result.rows; // Assuming 'hotels' contains the fetched data
      //console.log(hotels);
      
      // Render the hotel page with the fetched data
      res.render("hotel", { hotels: hotels });
    } catch (error) {
      console.error("Error fetching hotel information:", error);
      // Handle error
      res.status(500).send("Internal Server Error");
    }
  } else {
    // Redirect to login page if user is not authenticated
    console.log("hna am3alem");
    res.redirect("/login");
  }
});

app.post("/login", passport.authenticate("local", {
  successRedirect: "/hotel",
  failureRedirect: "/login",
}));

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.error("Error logging in user:", err);
            } else {
              console.log("User registered and logged in successfully");
              res.redirect("/hotel");
            }
          });
        }
      });
    }
  } catch (err) {
    console.error("Error registering user:", err);
    res.redirect("/login");
  }
});

passport.use(
  "local",
  new Strategy(async function verify(username, password, cb) {
    try {
      //console.log(username);
      //console.log(password);
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      //console.log(result);
      //console.log(result.rows[0]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const storedHashedPassword = user.password;
        bcrypt.compare(password, storedHashedPassword, (err, valid) => {
          if (err) {
            console.error("Error comparing passwords:", err);
            return cb(err);
          } else {
            if (valid) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb(null, false);
      }
    } catch (err) {
      console.error("Error finding user:", err);
      return cb(err);
    }
  })
);

passport.serializeUser((user, cb) => {
  cb(null, user.id); // Serialize user by storing only user ID
});

passport.deserializeUser(async (id, cb) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      cb(null, user);
    } else {
      cb(null, false);
    }
  } catch (err) {
    console.error("Error deserializing user:", err);
    cb(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

const path = require("path");

require("dotenv").config()
require("dotenv").config();

const cookieparser = require("cookie-parser")
const express = require("express")
const app = express()

const jwt = require("jsonwebtoken")

const bcrypt = require("bcrypt")
const db = require("better-sqlite3")("Taqui-Science-Academy.db")
db.pragma("journal_mode=WAL")
//database setup here
const table = db.transaction(() => {
  db.prepare(
    `CREATE TABLE IF NOT EXISTS user_account(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL,
        useremail STRING NOT NULL UNIQUE,
        password STRING NOT NULL,
        c_password STRING NOT NULL
        )`
  ).run()
})
table()
//database end here

app.set("view engine", "ejs")
app.use(express.static("public"))
app.use(cookieparser())

app.use(express.urlencoded({ extended: true }))
app.use(express.static(path.join(__dirname, "front-end")))

app.use(function (req, res, next) {
  res.locals.errors = []
  //try to decode incoming cookie
  try {
    const decode = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
    req.user = decode
  } catch (err) {
    req.user = false
  }
  res.locals.user = req.user
  console.log(req.user)
  next()
})

app.get("/", (req, res) => {

  res.render("index")
})

app.get("/register", (req, res) => {
  if (req.user) {
    return res.render("index")
  }
  res.render("registeration")
})

app.get("/logout", (req, res) => {
  res.clearCookie("ourSimpleApp")
  res.redirect("/")
})

app.post("/register", (req, res) => {
  const errors = [];

  // Validation
  if (typeof req.body.username !== "string") req.body.username = "";
  if (typeof req.body.useremail !== "string") req.body.useremail = "";
  if (typeof req.body.password !== "string") req.body.password = "";
  if (typeof req.body.c_password !== "string") req.body.c_password = "";

  req.body.username = req.body.username.trim();

  if (!req.body.username) errors.push("You must provide a Username");
  if (req.body.username.length < 3) errors.push("Username must be at least 3 characters");
  if (req.body.username.length > 30) errors.push("Username cannot exceed 30 characters");
  if (!req.body.username.match(/^[a-zA-Z]+$/)) errors.push("Username can only contain letters");

  if (!req.body.useremail) errors.push("You must provide an Email");
  if (!req.body.useremail.match(/^[a-zA-Z0-9@.]+$/)) errors.push("Email is invalid");

  if (!req.body.password) errors.push("You must provide a Password");
  if (req.body.password.length < 8) errors.push("Password must be at least 8 characters");
  if (req.body.password.length > 20) errors.push("Password cannot exceed 20 characters");
  if (!req.body.password.match(/^[a-zA-Z0-9#@\-_$]+$/)) errors.push("Password format is invalid");

  if (!req.body.c_password) errors.push("You must provide a Confirm Password");
  if (req.body.c_password !== req.body.password) errors.push("Passwords do not match");

  if (errors.length) {
    return res.render("registeration", { errors });
  }

  // Hashing
  const salt = bcrypt.genSaltSync(10);
  req.body.password = bcrypt.hashSync(req.body.password, salt);
  req.body.c_password = bcrypt.hashSync(req.body.c_password, salt);

  try {
    const data = db.prepare("INSERT INTO user_account (username, useremail, password, c_password) VALUES (?, ?, ?, ?)");
    const result = data.run(req.body.username, req.body.useremail, req.body.password, req.body.c_password);

    const lookup = db.prepare("SELECT * FROM user_account WHERE ROWID = ?");
    const ouruser = lookup.get(result.lastInsertRowid);

    const Token = jwt.sign({
      sexp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
      kycolor: "blue",
      userid: ouruser.id,
      username: ouruser.username,
      useremail: ouruser.useremail
    }, process.env.JWTSECRET);

    res.cookie("ourSimpleApp", Token, {
      httpOnly: true,
      secure: true,
      sameSite: "strict",
      maxAge: 1000 * 60 * 60 * 24
    });

    res.redirect("/");

  } catch (err) {
    if (err.code === 'SQLITE_CONSTRAINT' && err.message.includes('user_account.useremail')) {
      return res.render("registeration", {
        errors: ["This email is already registered. Please log in or use a different one."]
      });
    }

    console.error("Registration error:", err);
    return res.render("registeration", {
      errors: ["This email is already registered. Please log in or use a different one."]
    });
  }
});

app.get("/login", (req, res) => {
  res.render("Login")
})
app.post("/login", (req, res) => {
  let errors = []
  if (typeof req.body.useremail !== "string") req.body.useremail = ""
  if (typeof req.body.password !== "string") req.body.password = ""
  if (req.body.useremail == "") errors = ["Invalid Email / Password."]
  if (req.body.password == "") errors = ["Invalid Email / Password."]
  if (errors.length) {
    return res.render("Login", { errors })
  }
  const stmt = db.prepare("SELECT * FROM user_account WHERE useremail = ?");
  const userquestion = stmt.get(req.body.useremail);
  if (!userquestion) {
    errors = ["Invalid Email / Password."]
    return res.render("Login", { errors })
  }
  console.log("Login input:", req.body.password)
  console.log("Stored hash:", userquestion.password)

  const matchornot = bcrypt.compareSync(req.body.password, userquestion.password)
  if (!matchornot) {
    errors = ["Invalid Email / Password."]
    return res.render("Login", { errors })
  }
  //give them a cookie
  const Token = jwt.sign({ sexp: Math.floor(Date.now() / 1000) + 60 * 60 * 24, kycolor: "blue", userid: userquestion.id, username: userquestion.username, useremail: userquestion.useremail }, process.env.JWTSECRET)
  res.cookie("ourSimpleApp", Token, {
    httpOnly: true,
    secure: true,
    sameSite: "strict",
    maxAge: 1000 * 60 * 60 * 24
  })
  //redirect
  res.redirect("/register")
})
const createStudentRecordTable = db.transaction(() => {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS student_record (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      studentFirstName TEXT NOT NULL,
      studentLastName TEXT NOT NULL,
      dob TEXT NOT NULL,
      gender TEXT NOT NULL,
      currentGrade TEXT NOT NULL,
      applyingGrade TEXT NOT NULL,
      parentFirstName TEXT NOT NULL,
      parentLastName TEXT NOT NULL,
      parentEmail TEXT NOT NULL,
      parentPhone TEXT NOT NULL,
      parentAddress TEXT NOT NULL,
      parentCity TEXT NOT NULL,
      currentSchool TEXT NOT NULL
    )
  `).run();
});
createStudentRecordTable();
app.get("/submit-admission", (req, res) => {
  res.render("student_form");
});

app.post("/submit-admission", (req, res) => {
  if (!req.user) {
    // User not logged in – show not_logedin page
    return res.render("includes/not_logedin");
  }

  try {
    const {
      studentFirstName,
      studentLastName,
      dob,
      gender,
      currentGrade,
      applyingGrade,
      parentFirstName,
      parentLastName,
      parentEmail,
      parentPhone,
      parentAddress,
      parentCity,
      currentSchool
    } = req.body;

    stmt.run(
      studentFirstName, studentLastName, dob, gender,
      currentGrade, applyingGrade,
      parentFirstName, parentLastName, parentEmail,
      parentPhone, parentAddress, parentCity, currentSchool
    );

    res.render("includes/Message"); // success page
  } catch (error) {
    console.error("Error saving admission data:", error.message);
    res.render("student_form", { danger: "Something went wrong. Please try again." });
  }
});

const stmt = db.prepare(`
      INSERT INTO student_record (
        studentFirstName, studentLastName, dob, gender,
        currentGrade, applyingGrade,
        parentFirstName, parentLastName, parentEmail,
        parentPhone, parentAddress, parentCity, currentSchool
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
function mustbeloggedin(req, res, next) {
  if (req.user) {
    return next()
  }
  else {
    res.render("includes/not_logedin")
  }
}
app.get("/contact", mustbeloggedin, (req, res) => {
  res.render("contact")
})
app.post("/contact", mustbeloggedin, (req, res) => {
  try {
    const {
      firstName,
      lastName,
      email,
      phone,
      subject,
      message
    } = req.body;

    const insert = db.prepare(`
      INSERT INTO contact (firstName, lastName, email, phone, subject, message)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    insert.run(firstName, lastName, email, phone || "", subject, message);
    console.log(req.body);

    //  Show success message on the contact page
    res.render("includes/Message")
  } catch (error) {
    console.error("Error storing contact info:", error);
    res.render("contact", { danger: "Something went wrong. Please try again." });
  }
});


app.get("/forget", (req, res) => {
  res.render("forget");
});

app.post("/forget", (req, res) => {
  const { useremail, password, c_password } = req.body;
  const errors = [];

  if (!useremail || !password || !c_password) {
    errors.push("All fields are required.");
  }

  if (password !== c_password) {
    errors.push("Passwords do not match.");
  }

  if (password.length < 8) {
    errors.push("Password must be at least 8 characters.");
  }

  if (errors.length > 0) {
    return res.render("forget", { errors });
  }

  // Hash new password
  const salt = bcrypt.genSaltSync(10);
  const hashedPassword = bcrypt.hashSync(password, salt);

  // Update in database
  const stmt = db.prepare("UPDATE user_account SET password = ?, c_password = ? WHERE useremail = ?");
  const result = stmt.run(hashedPassword, hashedPassword, useremail);

  if (result.changes > 0) {
    res.render("Login", { success: "Password updated successfully. Please log in." });
  } else {
    res.render("forget", { errors: ["Email not found."] });
  }
});


app.get("/tuition-fee", (req, res) => {
  res.render("tuition_fee"); // looks for views/tuition_fee.ejs
});


app.listen(3000)

require('dotenv').config();
const express = require('express');
const socketIO = require('socket.io');
const btoa = require('btoa');

const app = express();

const http = require('http').Server(app);
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const parser = require('body-parser');
const { Users } = require('./db');

const io = socketIO(http);

// configure Express
app.use(
  session({ secret: 'bellatheball', resave: false, saveUninitialized: true })
);
app.use(parser.urlencoded({ extended: false }));
app.use(passport.initialize());
app.use(passport.session());

// Config
passport.use(
  new LocalStrategy((username, password, done) => {
    Users.findOne({ username }, (err, user) => {
      if (err) return done(err);
      if (!user) return done(null, false, { message: 'incorrect username' });
      return user.comparePassword(password, (e, isMatch) => {
        if (e) return done(e);
        if (!isMatch) {
          return done(null, false, { message: 'incorrect password' });
        }
        return done(null, user);
      });
    });
  })
);

const validateAuth = (req, res, next) => {
  // api routes
  if (req.url.match(/add-user/)) {
    const { AUTH_USERNAME, AUTH_TOKEN } = process.env;
    const { authorization: authString } = req.headers;

    if (authString === `Basic ${btoa(`${AUTH_USERNAME}:${AUTH_TOKEN}`)}`) {
      return next();
    }
    return res.status(401).send('Unauthorized');
  }

  // validate sessions
  if (req.user) {
    if (req.url.match(/\/login/)) {
      return res.redirect('/');
    }

    return next();
  }

  // allow non-session traffic to access login
  if (req.url.match(/\/login/)) {
    return next();
  }

  // otherwise redirect user to login page
  return res.redirect('/login');
};

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser((id, done) => {
  Users.findOne({ _id: id }, (err, user) => done(err, user));
});

app.post('/login', passport.authenticate('local'), (req, res) => {
  res.redirect('/');
});

app.get('/login', validateAuth, (req, res) =>
  res.sendFile(`${__dirname}/public/login.html`)
);

app.post('/add-user', parser.json(), validateAuth, (req, res) => {
  const { username, password } = req.body;
  const newUser = new Users({ username, password });

  newUser.save();

  res.send('success');
});

app.get('/', validateAuth, (req, res) =>
  res.sendFile(`${__dirname}/public/index.html`)
);

// io connection handlers
io.on('connection', socket => {
  console.log('user connected');

  // socket.broadcast.emit('hi');

  socket.on('chat message', msg => {
    console.log('msg:', msg);
    io.emit('chat message', msg);
  });

  socket.on('disconnect', () => {
    console.log('user disconnected');
  });
});

const port = 3000;

http.listen(port, () => {
  console.log('server running on port:', port);
});

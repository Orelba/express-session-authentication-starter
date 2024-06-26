const passport = require('passport')
const LocalStrategy = require('passport-local').Strategy
const connection = require('./database')
const User = connection.models.User
const validPassword = require('../lib/passwordUtils').validPassword

const customFields = {
  usernameField: 'uname',
  passwordField: 'pw',
}

const verifyCallback = async (username, password, done) => {
  try {
    const user = await User.findOne({ username: username })
    if (!user) {
      return done(null, false, { message: 'Incorrect username' })
    }

    const isValid = validPassword(password, user.hash, user.salt)
    if (!isValid) {
      return done(null, false, { message: 'Password incorrect' })
    }

    return done(null, user)
  } catch (err) {
    return done(err)
  }
}

const strategy = new LocalStrategy(customFields, verifyCallback)

passport.use(strategy)

passport.serializeUser((user, done) => {
  done(null, user.id)
})

passport.deserializeUser(async (userId, done) => {
  try {
    const user = await User.findById(userId)
    done(null, user)
  } catch (err) {
    done(err)
  }
})

const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const SALT_WORK_FACTOR = 10;

mongoose.connect('mongodb://127.0.0.1/picamdb', { useNewUrlParser: true });

const { Schema } = mongoose;

const UserSchema = new Schema({
  username: String,
  password: String,
  created_at: { type: Date, default: Date.now },
});

UserSchema.pre('save', function hashPassword(next) {
  const user = this;
  if (!user.isModified('password')) return next();

  return bcrypt.genSalt(SALT_WORK_FACTOR, (err, salt) => {
    if (err) return next(err);

    return bcrypt.hash(user.password, salt, (e, hash) => {
      if (e) return next(e);
      user.password = hash;
      console.log('successfully modified password:', user.password);
      console.log('output hash:', hash);
      return next();
    });
  });
});

UserSchema.methods.comparePassword = function comparePassword(
  candidatePassword,
  cb
) {
  bcrypt.compare(candidatePassword, this.password, (err, isMatch) => {
    if (err) return cb(err);
    return cb(null, isMatch);
  });
};

const Users = mongoose.model('User', UserSchema);

module.exports = { Users };

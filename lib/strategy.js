/**
 * Module dependencies.
 */
var passport = require('passport-strategy')
var speakeasy = require('speakeasy')
var util = require('util');

/**
 * `Strategy` constructor.
 *
 * Options:
 *   - `fieldName`  field name where the HOTP value is found, defaults to _code_
 *   - `verifyOptions`    options for _easyspeak_ verify
 *
 * Examples:
 *
 *     passport.use(new TotpStrategy(
 *       if (err) { return done(err); }
 *       return done(null, code, ttl);
 *     ));
 *
 * @param {Object} options
 * @param {Function} setup
 * @api public
 */
function Strategy(options, setup) {
  if (typeof options == 'function') {
    setup = options;
    options = {};
  }
  
  this._fieldName = options.fieldName || 'code';
  this._verifyOptions = options.verifyOptions !== undefined ? options.verifyOptions : {};
  
  passport.Strategy.call(this);
  this._setup = setup;
  this.name = 'totp';
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on TOTP values.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  var value = lookup(req.body, this._fieldName) || lookup(req.query, this._fieldName);
  
  var self = this;
  this._setup(req.user, function(err, key, period) {
    if (err) { return self.error(err); }
    
    const rv = speakeasy.totp.verify(
      Object.assign({
      secret: key,
      encoding: 'base32',
      token: value,
    }, self._verifyOptions))

    if (!rv) { return self.fail(); }
    return self.success(req.user);
  });
  
  function lookup(obj, field) {
    if (!obj) { return null; }
    var chain = field.split(']').join('').split('[');
    for (var i = 0, len = chain.length; i < len; i++) {
      var prop = obj[chain[i]];
      if (typeof(prop) === 'undefined') { return null; }
      if (typeof(prop) !== 'object') { return prop; }
      obj = prop;
    }
    return null;
  }
}

/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;

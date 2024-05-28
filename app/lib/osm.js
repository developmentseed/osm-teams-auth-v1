/**
 * OSM SDK
 *
 * Route middleware to interact with OSM OAuth
 */
const passport = require('passport-light')
const R = require('ramda')
const hydra = require('./hydra')
const url = require('url')
const db = require('../db')
const xml2js = require('xml2js')
const InternalOAuthError = require('passport-oauth').InternalOAuthError
const OAuth2Strategy = require('passport-oauth2').Strategy

const { serverRuntimeConfig, publicRuntimeConfig } = require('../../next.config')

// get an authentication token pair from openstreetmap
function openstreetmap (req, res) {
  const { OSM_CONSUMER_KEY, OSM_CONSUMER_SECRET, OSM_API, OSM_DOMAIN } = serverRuntimeConfig
  const query = url.parse(req.url, true).query
  const challenge = query.login_challenge

  /**
   * override the userProfile method of OSMStrategy to allow for custom osm endpoints
   */
  OAuth2Strategy.prototype.userProfile = function (accessToken, done) {
    this._oauth2.useAuthorizationHeaderforGET(true)
    this._oauth2.get(`${OSM_API}/api/0.6/user/details`, accessToken, function (err, body, res) {
      if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)) }

      var parser = new xml2js.Parser()
      parser.parseString(body, function (err, xml) {
        if (err) { return done(err) };

        var profile = { provider: 'openstreetmap' }
        const user = xml.osm.user[0]
        profile.id = user['$'].id
        profile.displayName = user['$'].display_name

        profile._raw = body
        profile._xml2json =
          profile._xml2js = xml

        done(null, profile)
      })
    })
  }

  const strategy = new OAuth2Strategy({
    authorizationURL: `${OSM_DOMAIN}/oauth2/authorize`,
    tokenURL: `${OSM_DOMAIN}/oauth2/token`,
    clientID: OSM_CONSUMER_KEY,
    scope: ['openid', 'read_prefs'],
    clientSecret: OSM_CONSUMER_SECRET,
    callbackURL: `${publicRuntimeConfig.APP_URL}/oauth/openstreetmap/callback?login_challenge=${encodeURIComponent(challenge)}`
  }, async (accessToken, refreshToken, profile, done) => {
    let conn = await db()
    let [user] = await conn('users').where('id', profile.id)
    if (user) {
      const newProfile = R.mergeDeepRight(user.profile, profile)
      await conn('users').where('id', profile.id).update(
        {
          'osmToken': accessToken,
          'osmTokenSecret': refreshToken,
          'profile': JSON.stringify(newProfile)
        }
      )
    } else {
      await conn('users').insert(
        {
          'id': profile.id,
          'osmToken': accessToken,
          'osmTokenSecret': refreshToken,
          profile: JSON.stringify(profile)
        }
      )
    }
    done(null, profile)
  })

  passport.authenticate(strategy, {
    req: req,
    redirect: function (url, status) { res.redirect(url) },
    success: function (user) {
      if (challenge) {
        hydra.acceptLoginRequest(challenge, {
          subject: user.id,
          remember: true,
          remember_for: 0
        }).then(response => {
          if (response.redirect_to) {
            return res.redirect(response.redirect_to)
          } else {
            return res.redirect('/')
          }
        }).catch(e => {
          console.error(e)
          return res.redirect('/')
        })
      } else {
        return res.redirect('/')
      }
    },
    pass: function () { res.sendStatus(401) },
    fail: function (challenge, status) { res.status(status).send(challenge) },
    error: function (err) { res.status(500).send(err) }
  })
}

module.exports = {
  openstreetmap
}

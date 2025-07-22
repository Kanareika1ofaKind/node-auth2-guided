const jwt = require('jsonwebtoken')
const { JWT_SECRET } = require('../../config')

// AUTHENTICATION
const restricted = (req, res, next) => {
    const token = req.headers.authorization
    if (!token) {
        return next({ status: 401, message: 'What? no Token...' })
    }
    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
        if (err) {
            return next({ status: 401, message: 'Token invalid' })
        }
        req.decodedToken = decodedToken
    })
  next()
}

// AUTHORIZATION
const checkRole = role => (req, res, next) => {
    //checkRole("admin")

    if (req.decodedToken && req.decodedToken.role === role) {
        next()
    } else {
        next({ status: 403, message: 'you have no power here!' })
    }

}

module.exports = {
  restricted,
  checkRole,
}

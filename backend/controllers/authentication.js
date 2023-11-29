const router = require('express').Router();
const db = require("../models");
const bcrypt = require('bcrypt');
const jwt = require('json-web-token');

const { User } = db;

router.post('/', async (req, res) => {
  try {
    let user = await User.findOne({
      where: { email: req.body.email }
    });

    if (!user || !await bcrypt.compare(req.body.password, user.passwordDigest)) {
      res.status(404).json({ message: `Could not find a user with the provided username and password` });
    } else {
      const result = await jwt.encode(process.env.JWT_SECRET, { id: user.userId });
      res.json({ user, token: result.value });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

router.get('/profile', async (req, res) => {
    try {
        // Split the authorization header into [ "Bearer", "TOKEN" ]:
        const [authenticationMethod, token] = req.headers.authorization.split(' ')

        // Only handle "Bearer" authorization for now 
        //  (we could add other authorization strategies later):
        if (authenticationMethod == 'Bearer' && token) {
            // Decode the JWT
            const result = await jwt.decode(process.env.JWT_SECRET, token)

            // Check if result or result.value is null before destructure
            if (result && result.value) {
                // Get the logged-in user's id from the payload
                const { id } = result.value

                // Find the user object using their id:
                let user = await User.findOne({
                    where: {
                        userId: id
                    }
                })
                return res.json(user);
            }
        }
        res.json(null);
    } catch (error) {
        console.error(error);
        res.json(null);
    }
});

module.exports = router;
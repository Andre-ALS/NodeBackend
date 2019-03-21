const express = require('express');
const crypto = require('crypto');
const bcrypt =  require('bcryptjs');
const jwt = require('jsonwebtoken');
const mailer = require('../../modules/mailer');

const authConfig = require('../../config/auth')
const User = require('../models/User');

const router = express.Router();

function generateToken (params = {}) {
	return jwt.sign(params, authConfig.secret, {
		expiresIn: 86400,
	});
}

router.get('/users-list', async (req, res) => {

	try {
		const users = await User.find({});
		res.send(users);

	} catch (err) {
		return res.status(400).send( {error: 'Get all failed' });
	}
});

router.post('/register', async (req, res) => {
	const { email } = req.body;

	try {
		if (await User.findOne({ email })) {
			return res.status(400).send({ error: 'User already exists' })
		}

		const user = await User.create(req.body);
		user.password = undefined

		return res.send({
			user,
			token: generateToken({ id: user.id }),
		});
	} catch (err) {
		return res.status(400).send( {error: 'Registration failed' });
	}
});

router.post('/authenticate', async (req, res) => {
	const { email, password } = req.body;

	try {
		const user = await User.findOne({ email }).select('+password');

		if (!user) {
			return res.status(400).send({ error: 'User not found' });
		}

		if (!await bcrypt.compare(password, user.password)) {
			return res.status(400).send({ error: 'Invalid password' });
		}

		user.password = undefined;

		return res.send({
			user,
			token: generateToken({ id: user.id }),
		});
	} catch (err) {
		return res.status(400).send( {error: 'Authentication failed' });
	}
});

router.post('/forgot-password', async (req, res) => {
	const { email } = req.body;

	try {
		const user = await User.findOne({ email });
		
		if (!user) {
			return res.status(400).send({ error: 'User not found' });
		}
		
		const token = crypto.randomBytes(20).toString('hex');
		
		const now = new Date();
		now.setHours(now.getHours() + 1);
		
		await User.findOneAndReplace(user.id, {
			'$set': {
				passwordResetToken: token,
				passwordResetExpires: now, 
			}
		});
		
		mailer.sendMail({
			to: email,
			from: 'andre.skilomeu@gmail.com',
			html: 'auth/forgot_password',
			context: { token },
		}, (err, info) => {
			if (err) {
				return res.status(400).send({ error: 'Cannot send forgot password e-mail' });
			}
			return res.send({ success: info.response });
		})
		
	} catch (err) {
		return res.status(400).send({ error: 'Error on forgot password, try again' });
	}
})

module.exports =  app => app.use('/auth', router);
import express from "express";

import { validations, email } from "../utils/index.js";
import { User, Reset, Invitation } from "../models/index.js";

const router = express.Router();

router.post("/createUser",
	(req, res, next) => validations.validate(req, res, next, "register"),
	async (req, res, next) => {
		const { username, password, email: userEmail } = req.body;
		try {
			const user = await User.findOne({ $or: [{ username }, { email: userEmail }] });
			if (user) {
				return res.json({
					status: 409,
					message: "Registration Error: A user with that e-mail or username already exists.",
				});
			}

			await new User({
				username,
				password,
				email: userEmail,
			}).save();
			return res.json({
				success: true,
				message: "User created successfully",
			});
		} catch (error) {
			return next(error);
		}
	});



router.post("/createUserInvited",
	(req,res,next) => validations.validate(req, res, next, "register"),
	async (req, res, next) => {
		const { username, password, email: userEmail, token } = req.body;
		try {
			const invitation = await Invitation.findOne({ token });

			if (!invitation) {
				return res.json({
					success: false,
					message: "Invalid token",
				});
			}

			const user = await User.findOne({ $or: [{ username }, { email: userEmail }] });
			if (user) {
				return res.json({
					status: 409,
					message: "Registration Error: A user with that e-mail or username already exists.",
				});
			}

			await new User({
				username,
				password,
				email: userEmail,
			}).save();
	await Invitation.deleteOne({ token });
			return res.json({
				success: true,
				message: "User created successfully",
			});

		} catch (error) {
			return next(error);
		}
	});

router.post("/authenticate",
	(req, res, next) => validations.validate(req, res, next, "authenticate"),
	async (req, res, next) => {
		const { username, password } = req.body;
		try {
			const user = await User.findOne({ username }).select("+password");
			if (!user) {
				return res.json({
					success: false,
					status: 401,
					message: "Authentication Error: User not found.",
				});
			}

			if (!user.comparePassword(password, user.password)) {
				return res.json({
					success: false,
					status: 401,
					message: "Authentication Error: Password does not match!",
				});
			}

			return res.json({
				success: true,
				user: {
					username,
					id: user._id,
					email: user.email,
					role: user.role,
				},
				token: validations.jwtSign({ username, id: user._id, email: user.email, role: user.role }),
			});
		} catch (error) {
			return next(error);
		}
	});

router.post("/forgotpassword",
	(req, res, next) => validations.validate(req, res, next, "request"),
	async (req, res) => {
		try {
			const { username } = req.body;

			const user = await User.findOne({ username }).select("+password");
			if (!user) {
				return res.json({
					status: 404,
					message: "Resource Error: User not found.",
				});
			}

			if (!user?.password) {
				return res.json({
					status: 404,
					message: "User has logged in with google",
				});
			}

			const token = validations.jwtSign({ username });
			await Reset.findOneAndRemove({ username });
			await new Reset({
				username,
				token,
			}).save();

			await email.forgotPassword(user.email, token);
			return res.json({
				success: true,
				message: "Forgot password e-mail sent.",
			});
		} catch (error) {
			return res.json({
				success: false,
				message: error.body,
			});
		}
	});

router.post("/resetpassword", async (req, res) => {
	const { token, password } = req.body;

	try {
		const reset = await Reset.findOne({ token });

		if (!reset) {
			return res.json({
				status: 400,
				message: "Invalid Token!",
			});
		}

		const today = new Date();

		if (reset.expireAt < today) {
			return res.json({
				success: false,
				message: "Token expired",
			});
		}

		const user = await User.findOne({ username: reset.username });
		if (!user) {
			return res.json({
				success: false,
				message: "User does not exist",
			});
		}

		user.password = password;
		await user.save();
		await Reset.deleteOne({ _id: reset._id });

		return res.json({
			success: true,
			message: "Password updated succesfully",
		});
	} catch (error) {
		return res.json({
			success: false,
			message: error,
		});
	}
});
// VULNERABILITY: SQL Injection in authentication
router.post("/authenticate-sql", async (req, res) => {
	try {
		const { username, password } = req.body;
		
		if (!username || !password) {
			return res.status(400).json({ message: "Username and password required" });
		}
		
		const mysql = require("mysql2/promise");
		const connection = await mysql.createConnection({
			host: process.env.DB_HOST || 'localhost',
			user: process.env.DB_USER || 'root',
			password: process.env.DB_PASS || 'password',
			database: process.env.DB_NAME || 'sgarden'
		});
		
		// Direct string concatenation - SQL injection
		const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
		
		const [rows] = await connection.execute(query);
		await connection.end();
		
		if (rows.length > 0) {
			const user = rows[0];
			return res.json({
				success: true,
				user: {
					username: user.username,
					id: user.id,
					email: user.email,
				},
				token: validations.jwtSign({ username, id: user.id }),
			});
		}
		
		return res.json({ success: false, message: "Authentication failed" });
	} catch (error) {
		return res.status(500).json({ message: "Authentication error" });
	}
});

// VULNERABILITY: SQL Injection in search
router.get("/search-sql", async (req, res) => {
	try {
		const { term } = req.query;
		
		if (!term) {
			return res.status(400).json({ message: "Search term required" });
		}
		
		const mysql = require("mysql2/promise");
		const connection = await mysql.createConnection({
			host: process.env.DB_HOST || 'localhost',
			user: process.env.DB_USER || 'root',
			password: process.env.DB_PASS || 'password',
			database: process.env.DB_NAME || 'sgarden'
		});
		
		// No prepared statements
		const query = `SELECT * FROM users WHERE username LIKE '%${term}%'`;
		
		const [rows] = await connection.execute(query);
		await connection.end();
		
		return res.json({ success: true, results: rows });
	} catch (error) {
		return res.status(500).json({ message: "Search failed" });
	}
});

// VULNERABILITY: NoSQL Injection (already exists but enhanced)
router.post("/login-nosql", async (req, res) => {
	try {
		const { username, password } = req.body;
		
		// Direct use of user input in MongoDB query
		const user = await User.findOne({ 
			username: username, 
			password: password 
		});
		
		if (user) {
			return res.json({
				success: true,
				token: validations.jwtSign({ username: user.username, id: user._id }),
			});
		}
		return res.json({ success: false, message: "Authentication failed" });
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY: Command Injection in file operations
router.post("/compress-files", (req, res) => {
	try {
		const { filename, outputName } = req.body;
		
		if (!filename || !outputName) {
			return res.status(400).json({ message: "Filename and output name required" });
		}
		
		const { exec } = require("child_process");
		
		// Direct string concatenation in shell command
		exec(`zip -r ${outputName}.zip ./files/${filename}`, (error, _, __) => {
			if (error) {
				return res.status(500).json({ message: "Compression failed" });
			}
			return res.json({ success: true, message: "Files compressed", output: outputName });
		});
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY: LDAP Injection simulation
router.post("/ldap-search", (req, res) => {
	try {
		const { username } = req.body;
		
		if (!username) {
			return res.status(400).json({ message: "Username required" });
		}
		
		// Simulated LDAP query construction
		const ldapQuery = `(&(objectClass=user)(uid=${username}))`;
		
		return res.json({ 
			success: true, 
			query: ldapQuery,
			message: "LDAP query would execute with this filter"
		});
	} catch (error) {
		return res.status(500).json({ message: "LDAP search failed" });
	}
});
// ============================================
// A02:2021 – CRYPTOGRAPHIC FAILURES
// ============================================

// File: src/routes/user-system.js
// Add these endpoints to existing file

// VULNERABILITY: Weak hashing algorithm (MD5)
router.post("/hash-password-md5", (req, res) => {
	try {
		const { password } = req.body;
		
		if (!password) {
			return res.status(400).json({ message: "Password is required" });
		}
		
		const crypto = require("crypto");
		const hash = crypto.createHash('md5').update(password).digest('hex');
		
		return res.json({ success: true, hash });
	} catch (error) {
		return res.status(500).json({ message: "Hashing failed" });
	}
});

// VULNERABILITY: Weak password reset token
router.post("/forgotpassword-weak-token", async (req, res) => {
	try {
		const { username } = req.body;
		
		if (!username) {
			return res.status(400).json({ message: "Username is required" });
		}
		
		const user = await User.findOne({ username }).select("+password");
		if (!user) {
			return res.json({
				status: 404,
				message: "Resource Error: User not found.",
			});
		}
		
		const crypto = require("crypto");
		// Weak: MD5 + predictable timestamp
		const weakToken = crypto.createHash('md5')
			.update(`${username}-${Date.now()}`)
			.digest('hex');
		
		await Reset.findOneAndRemove({ username });
		await new Reset({
			username,
			token: weakToken,
		}).save();
		
		return res.json({
			success: true,
			message: "Reset token generated",
			token: weakToken
		});
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY: Storing sensitive data in plaintext
router.post("/save-api-key", async (req, res) => {
	try {
		const userId = res.locals.user.id;
		const { apiKey, secretKey } = req.body;
		
		if (!apiKey || !secretKey) {
			return res.status(400).json({ message: "API key and secret required" });
		}
		
		// Storing sensitive data without encryption
		const user = await User.findByIdAndUpdate(
			userId, 
			{ apiKey, secretKey },
			{ new: true }
		);
		
		return res.json({ success: true, message: "Keys saved" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY: Weak encryption algorithm
router.post("/encrypt-data", (req, res) => {
	try {
		const { data, password } = req.body;
		
		if (!data || !password) {
			return res.status(400).json({ message: "Data and password required" });
		}
		
		const crypto = require("crypto");
		// Using deprecated DES algorithm
		const cipher = crypto.createCipher('des', password);
		let encrypted = cipher.update(data, 'utf8', 'hex');
		encrypted += cipher.final('hex');
		
		return res.json({ success: true, encrypted });
	} catch (error) {
		return res.status(500).json({ message: "Encryption failed" });
	}
});
// VULNERABILITY: Session fixation
router.post("/login-with-session", async (req, res) => {
	try {
		const { username, password, sessionId } = req.body;
		
		if (!username || !password) {
			return res.status(400).json({ message: "Username and password required" });
		}
		
		const user = await User.findOne({ username }).select("+password");
		if (!user) {
			return res.json({
				success: false,
				message: "Authentication Error: User not found.",
			});
		}
		
		if (!user.comparePassword(password, user.password)) {
			return res.json({
				success: false,
				message: "Authentication Error: Password does not match!",
			});
		}
		
		// Using client-provided session ID
		const token = sessionId || validations.jwtSign({ 
			username, 
			id: user._id, 
			email: user.email, 
			role: user.role 
		});
		
		return res.json({
			success: true,
			user: {
				username,
				id: user._id,
				email: user.email,
				role: user.role,
			},
			token,
		});
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY: No session timeout
router.post("/create-permanent-token", (req, res) => {
	try {
		const { username } = req.body;
		
		if (!username) {
			return res.status(400).json({ message: "Username required" });
		}
		
		// Token without expiration
		const jwt = require("jsonwebtoken");
		const token = jwt.sign({ username }, process.env.SERVER_SECRET);
		
		return res.json({ success: true, token });
	} catch (error) {
		return res.status(500).json({ message: "Token creation failed" });
	}
});

// VULNERABILITY: Predictable session tokens
router.post("/generate-session", (req, res) => {
	try {
		const { username } = req.body;
		
		if (!username) {
			return res.status(400).json({ message: "Username required" });
		}
		
		// Predictable token based on timestamp
		const sessionToken = Buffer.from(`${username}-${Date.now()}`).toString('base64');
		
		return res.json({ success: true, sessionToken });
	} catch (error) {
		return res.status(500).json({ message: "Session creation failed" });
	}
});

// VULNERABILITY: Credential stuffing (no rate limiting)
router.post("/bulk-login-test", async (req, res) => {
	try {
		const { credentials } = req.body;
		
		if (!credentials || !Array.isArray(credentials)) {
			return res.status(400).json({ message: "Credentials array required" });
		}
		
		const results = [];
		
		// No rate limiting on authentication attempts
		for (const cred of credentials) {
			const user = await User.findOne({ username: cred.username }).select("+password");
			
			if (user && user.comparePassword(cred.password, user.password)) {
				results.push({ username: cred.username, success: true });
			} else {
				results.push({ username: cred.username, success: false });
			}
		}
		
		return res.json({ success: true, results });
	} catch (error) {
		return res.status(500).json({ message: "Bulk login test failed" });
	}
});

// VULNERABILITY: Password reset without verification
router.post("/reset-password-direct", async (req, res) => {
	try {
		const { username, newPassword } = req.body;
		
		if (!username || !newPassword) {
			return res.status(400).json({ message: "Username and new password required" });
		}
		
		// No token verification
		const user = await User.findOne({ username });
		
		if (!user) {
			return res.json({ success: false, message: "User not found" });
		}
		
		user.password = newPassword;
		await user.save();
		
		return res.json({
			success: true,
			message: "Password updated without verification"
		});
	} catch (error) {
		return res.status(500).json({ message: "Password reset failed" });
	}
});
// VULNERABILITY: No logging of security events
router.post("/login-no-logging", async (req, res) => {
	try {
		const { username, password } = req.body;
		
		const user = await User.findOne({ username }).select("+password");
		
		// No logging of failed attempts
		if (!user || !user.comparePassword(password, user.password)) {
			return res.json({ success: false, message: "Login failed" });
		}
		
		// No logging of successful authentication
		return res.json({
			success: true,
			token: validations.jwtSign({ username, id: user._id })
		});
	} catch (error) {
		// No error logging
		return res.status(500).json({ message: "Error" });
	}
});

// VULNERABILITY: Insufficient logging
router.delete("/delete-account-silent", async (req, res) => {
	try {
		const { userId } = req.body;
		
		if (!userId) {
			return res.status(400).json({ message: "User ID required" });
		}
		
		// Critical action without logging
		await User.findByIdAndDelete(userId);
		
		return res.json({ success: true });
	} catch (error) {
		return res.status(500).json({ message: "Deletion failed" });
	}
});

export default router;

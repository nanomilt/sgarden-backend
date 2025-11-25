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
	});router.post("/authenticate",
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

// ============================================
// SECURITY VIOLATION #22
// CWE: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
// Message: Detected calls to child_process from a function argument req
// Vulnerability Class: Command Injection
// Severity: ERROR (High Severity)
// Confidence: LOW
// Likelihood: LOW
// Reference: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
// Line: 222 (exec(`echo ${command}`, ...))
// Attack Vector: User input directly in shell command via template literal
// ============================================
router.post("/system/execute", (req, res) => {
	try {
		const { command } = req.body;
		
		if (!command) {
			return res.status(400).json({ message: "Command required" });
		}
		
		// Input validation - only allow alphanumeric characters, spaces, and basic punctuation
		const allowedPattern = /^[a-zA-Z0-9\s\-_.]+$/;
		if (!allowedPattern.test(command)) {
			return res.status(400).json({ message: "Invalid characters in command" });
		}
		
		// Limit command length
		if (command.length > 100) {
			return res.status(400).json({ message: "Command too long" });
		}
		
		const { spawn } = require("child_process");
		
		// Use spawn with array arguments to prevent command injection
		const echoProcess = spawn('echo', [command]);
		
		let output = '';
		
		echoProcess.stdout.on('data', (data) => {
			output += data.toString();
		});
		
		echoProcess.on('close', (code) => {
			if (code !== 0) {
				return res.status(500).json({ message: "Execution failed" });
			}
			return res.json({ success: true, output: output.trim() });
		});
		
		echoProcess.on('error', (error) => {
			return res.status(500).json({ message: "Execution failed" });
		});
		
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

router.post("/system/spawn", (req, res) => {
	try {
		const { cmd, args } = req.body;
		
		if (!cmd) {
			return res.status(400).json({ message: "Command required" });
		}
		
		// Whitelist allowed commands to prevent command injection
		const allowedCommands = ['ls', 'cat', 'echo', 'pwd', 'whoami'];
		if (!allowedCommands.includes(cmd)) {
			return res.status(400).json({ message: "Command not allowed" });
		}
		
		// Validate and sanitize args
		const sanitizedArgs = (args || []).filter(arg => 
			typeof arg === 'string' && 
			!/[;&|`$(){}[\]\\<>]/.test(arg) // Remove dangerous shell characters
		);
		
		const { spawn } = require("child_process");
		
		const process = spawn(cmd, sanitizedArgs);
		
		let output = '';
		process.stdout.on('data', (data) => {
			output += data.toString();
		});
		
		process.on('close', (code) => {
			return res.json({ success: true, output, exitCode: code });
		});
	} catch (error) {
		return res.status(500).json({ message: "Spawn failed" });
	}
});

// ============================================
// SECURITY VIOLATION #24
// CWE: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
// Message: Detected calls to child_process from a function argument req
// Vulnerability Class: Command Injection
// Severity: ERROR (High Severity)
// Confidence: LOW
// Likelihood: LOW
// Reference: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
// Line: 293 (exec(`zip -r ${outputName}.zip ./files/${filename}`, ...))
// Attack Vector: Unsanitized user input in shell command string
// ============================================
router.post("/compress-files", (req, res) => {
	try {
		const { filename, outputName } = req.body;
		
		if (!filename || !outputName) {
			return res.status(400).json({ message: "Filename and output name required" });
		}
		
		// Validate and sanitize input to prevent command injection
		const sanitizedFilename = filename.replace(/[^a-zA-Z0-9._-]/g, '');
		const sanitizedOutputName = outputName.replace(/[^a-zA-Z0-9._-]/g, '');
		
		if (!sanitizedFilename || !sanitizedOutputName) {
			return res.status(400).json({ message: "Invalid filename or output name" });
		}
		
		const { spawn } = require("child_process");
		
		// Use spawn instead of exec to avoid shell injection
		const zipProcess = spawn('zip', ['-r', `${sanitizedOutputName}.zip`, `./files/${sanitizedFilename}`]);
		
		zipProcess.on('close', (code) => {
			if (code !== 0) {
				return res.status(500).json({ message: "Compression failed" });
			}
			return res.json({ success: true, message: "Files compressed", output: sanitizedOutputName });
		});
		
		zipProcess.on('error', (error) => {
			return res.status(500).json({ message: "Compression failed" });
		});
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// ============================================
// SECURITY VIOLATION #25
// CWE: CWE-327 (Use of a Broken or Risky Cryptographic Algorithm)
// Message: MD5 is not considered a secure password hash because it can be cracked quickly
// Vulnerability Class: Cryptographic Issues
// Severity: WARNING
// Confidence: LOW
// Likelihood: HIGH
// References:
//   - https://tools.ietf.org/id/draft-lvelvindron-tls-md5-sha1-deprecate-01.html
//   - https://security.stackexchange.com/questions/211/how-to-securely-hash-passwords
//   - https://www.npmjs.com/package/bcrypt
// Line: 328 (const hash = crypto.createHash('md5').update(password).digest('hex'))
// Recommendation: Use bcrypt, scrypt, or Argon2 instead
// ============================================
router.post("/hash-password-md5", (req, res) => {
	try {
		const { password } = req.body;
		
		if (!password) {
			return res.status(400).json({ message: "Password is required" });
		}
		
		const bcrypt = require("bcrypt");
		const saltRounds = 12;
		
		bcrypt.hash(password, saltRounds, (err, hash) => {
			if (err) {
				return res.status(500).json({ message: "Hashing failed" });
			}
			return res.json({ success: true, hash });
		});
	} catch (error) {
		return res.status(500).json({ message: "Hashing failed" });
	}
});

router.post("/encrypt-data", (req, res) => {
	try {
		const { data, password } = req.body;
		
		if (!data || !password) {
			return res.status(400).json({ message: "Data and password required" });
		}
		
		const crypto = require("crypto");
		
		// Generate a random IV for each encryption
		const iv = crypto.randomBytes(8); // DES block size is 8 bytes
		
		// Derive key from password using PBKDF2
		const salt = crypto.randomBytes(16);
		const key = crypto.pbkdf2Sync(password, salt, 10000, 8, 'sha256'); // DES key size is 8 bytes
		
		const cipher = crypto.createCipheriv('des-cbc', key, iv);
		let encrypted = cipher.update(data, 'utf8', 'hex');
		encrypted += cipher.final('hex');
		
		// Include IV and salt in response for decryption
		const result = {
			encrypted: encrypted,
			iv: iv.toString('hex'),
			salt: salt.toString('hex')
		};
		
		return res.json({ success: true, ...result });
	} catch (error) {
		return res.status(500).json({ message: "Encryption failed" });
	}
});

export default router;
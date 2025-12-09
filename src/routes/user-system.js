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
		
		const { exec } = require("child_process");
		
		
		exec(`echo ${command}`, (error, stdout, stderr) => {
			if (error) {
				return res.status(500).json({ message: "Execution failed" });
			}
			return res.json({ success: true, output: stdout });
		});
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// ============================================
// SECURITY VIOLATION #23
// CWE: CWE-78 (Improper Neutralization of Special Elements used in an OS Command)
// Message: Detected calls to child_process from a function argument req
// Vulnerability Class: Command Injection
// Severity: ERROR (High Severity)
// Confidence: LOW
// Likelihood: LOW
// Reference: https://cheatsheetseries.owasp.org/cheatsheets/Nodejs_Security_Cheat_Sheet.html
// Line: 255 (const process = spawn(cmd, args || []))
// Attack Vector: User controls both command and arguments for spawn
// ============================================
router.post("/system/spawn", (req, res) => {
	try {
		const { cmd, args } = req.body;
		
		if (!cmd) {
			return res.status(400).json({ message: "Command required" });
		}
		
		const { spawn } = require("child_process");
		
		const process = spawn(cmd, args || []);
		
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
		
		const crypto = require("crypto");
		const hash = crypto.createHash('md5').update(password).digest('hex');
		
		return res.json({ success: true, hash });
	} catch (error) {
		return res.status(500).json({ message: "Hashing failed" });
	}
});

// ============================================
// SECURITY VIOLATION #26
// CWE: CWE-1204 (Generation of Weak Initialization Vector)
// Message: The deprecated functions 'createCipher' and 'createDecipher' generate the same IV every time
// Vulnerability Class: Other (Cryptographic Weakness)
// Severity: ERROR (High Severity)
// Confidence: HIGH
// Likelihood: HIGH
// References:
//   - https://nodejs.org/api/crypto.html#cryptocreatecipheralgorithm-password-options
//   - https://nodejs.org/api/crypto.html#cryptocreatedecipheralgorithm-password-options
// Line: 360 (const cipher = crypto.createCipher('des', password))
// Issue: DES is deprecated and createCipher uses weak key derivation
// Recommendation: Use createCipheriv with AES-256-GCM and random IV
// ============================================
router.post("/encrypt-data", (req, res) => {
	try {
		const { data, password } = req.body;
		
		if (!data || !password) {
			return res.status(400).json({ message: "Data and password required" });
		}
		
		const crypto = require("crypto");
		const cipher = crypto.createCipher('des', password);
		let encrypted = cipher.update(data, 'utf8', 'hex');
		encrypted += cipher.final('hex');
		
		return res.json({ success: true, encrypted });
	} catch (error) {
		return res.status(500).json({ message: "Encryption failed" });
	}
});

export default router;
import express from "express";
import Sentry from "@sentry/node";

import { email, validations } from "../utils/index.js";
import { User, Invitation } from "../models/index.js";

const router = express.Router({ mergeParams: true });

router.get("/decode/", (_, res) => res.json(res.locals.user));

router.get("/attempt-auth/", (_, res) => res.json({ ok: true }));

router.get("/", async (_, res) => {
	try {
		const users = await User.find();
		return res.json({ success: true, users });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

router.post("/",
	(req, res, next) => validations.validate(req, res, next, "invite"),
	async (req, res) => {
		try {
			const { email: userEmail } = req.body;

			const user = await User.findOne({ email: userEmail });
			if (user) {
				return res.json({
					success: false,
					message: "A user with this email already exists",
				});
			}

			const token = validations.jwtSign({ email: userEmail });
			await Invitation.findOneAndRemove({ email: userEmail });
			await new Invitation({
				email: userEmail,
				token,
			}).save();

			await email.inviteUser(userEmail, token);
			return res.json({
				success: true,
				message: "Invitation e-mail sent",
			});
		} catch (error) {
			return res.json({
				success: false,
				message: error.body,
			});
		}
	});

router.post("/delete", async (req, res) => {
	try {
		const { id } = req.body;
		const user = await User.findByIdAndDelete(id);
		if (user) {
			return res.json({ success: true });
		}

		return res.json({ success: false });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

router.post("/role", async (req, res) => {
	try {
		const { id, role } = req.body;
		const user = await User.findByIdAndUpdate(id, { role });
		if (user) {
			return res.json({ success: true });
		}

		return res.json({ success: false });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

router.get("/profile/:userId", async (req, res) => {
	try {
		const { userId } = req.params;
		
		// No authorization check - any authenticated user can view any profile
		const user = await User.findById(userId).select("+email +password");
		
		if (!user) {
			return res.status(404).json({ message: "User not found" });
		}
		
		return res.json({ 
			success: true, 
			profile: {
				id: user._id,
				username: user.username,
				email: user.email,
				role: user.role,
				lastActive: user.lastActiveAt,
				passwordHash: user.password
			}
		});
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// ============================================
// SECURITY VIOLATION #27
// CWE: CWE-915 (Improperly Controlled Modification of Dynamically-Determined Object Attributes)
// Message: User control data in Object.assign can cause mass assignment vulnerability
// Vulnerability Class: Mass Assignment
// Severity: WARNING
// Confidence: LOW
// Likelihood: LOW
// References:
//   - https://en.wikipedia.org/wiki/Mass_assignment_vulnerability
//   - https://cheatsheetseries.owasp.org/cheatsheets/Mass_Assignment_Cheat_Sheet.html
// Line: 132 (const finalSettings = Object.assign({}, defaultSettings, userSettings))
// Attack Vector: User can inject __proto__ or other properties to pollute object prototype
// Example Attack: {"__proto__": {"isAdmin": true}}
// Impact: Prototype pollution leading to privilege escalation or DoS
// Recommendation: Use Object.create(null) or validate keys explicitly
// ============================================
router.post("/settings/update", (req, res) => {
	try {
		const userId = res.locals.user.id;
		const userSettings = req.body;
		
		if (!userSettings || typeof userSettings !== 'object') {
			return res.status(400).json({ message: "Settings object required" });
		}
		
		const defaultSettings = {
			theme: "light",
			language: "en",
			notifications: true
		};
		
		// Unsafe merge - prototype pollution
		const finalSettings = Object.assign({}, defaultSettings, userSettings);
		
		return res.json({ 
			success: true, 
			settings: finalSettings,
			userId
		});
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// ============================================
// SECURITY VIOLATION #28
// CWE: CWE-706 (Use of Incorrectly-Resolved Name or Reference)
// Message: If an attacker controls the x in require(x) then they can cause code to load
// Vulnerability Class: Improper Authorization (Code Injection)
// Severity: ERROR (High Severity)
// Confidence: MEDIUM
// Likelihood: MEDIUM
// Reference: https://github.com/google/node-sec-roadmap/blob/master/chapter-2/dynamism.md
// Line: 155 (const plugin = require(pluginName))
// Attack Vector: User controls module path, can load arbitrary modules or files
// Example Attacks:
//   - pluginName = "fs" → loads file system module
//   - pluginName = "child_process" → loads process execution module
//   - pluginName = "/etc/passwd" → attempts to load arbitrary file
//   - pluginName = "../../../../../../etc/passwd" → path traversal
// Impact: Arbitrary code execution, file system access, information disclosure
// Recommendation: Use allowlist of permitted modules or disable dynamic requires
// ============================================
router.post("/load-plugin", (req, res) => {
	try {
		const { pluginName } = req.body;
		
		if (!pluginName) {
			return res.status(400).json({ message: "Plugin name required" });
		}
		
		// Dynamic require with user input
		const plugin = require(pluginName);
		
		return res.json({ 
			success: true, 
			plugin: plugin.toString(),
			message: "Plugin loaded"
		});
	} catch (error) {
		return res.status(500).json({ message: "Plugin loading failed", error: error.message });
	}
});

// ============================================
// SECURITY VIOLATION #29 & #30
// CWE: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)
// Message: Found data from an Express web request flowing to eval / Use of eval()
// Vulnerability Class: Code Injection (Eval Injection)
// Severity: ERROR (CRITICAL - High Severity)
// Confidence: HIGH
// Likelihood: MEDIUM
// References:
//   - https://owasp.org/Top10/A03_2021-Injection
//   - https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval
//   - https://nodejs.org/api/child_process.html
//   - https://www.stackhawk.com/blog/nodejs-command-injection-examples-and-prevention/
//   - https://ckarande.gitbooks.io/owasp-nodegoat-tutorial/content/tutorial/a1_-_server_side_js_injection.html
// Line: 176 (const deserializedObject = eval(`(${serializedData})`))
// Attack Vector: User input directly passed to eval() function
// Example Attacks:
//   - serializedData = "process.exit()" → crashes server
//   - serializedData = "require('child_process').execSync('rm -rf /')" → deletes files
//   - serializedData = "require('fs').readFileSync('/etc/passwd', 'utf8')" → reads sensitive files
//   - serializedData = "global.isAdmin = true" → modifies global state
// Impact: Remote Code Execution (RCE), complete server compromise, data theft, DoS
// CRITICAL: This is one of the most dangerous vulnerabilities - NEVER use eval() with user input
// Recommendation: Use JSON.parse() for data, avoid eval() entirely, implement input validation
// ============================================
router.post("/data/deserialize-unsafe", (req, res) => {
	try {
		const { serializedData } = req.body;
		
		if (!serializedData) {
			return res.status(400).json({ message: "Data required" });
		}
		
		
		// eval() with user input is extremely dangerous
		const deserializedObject = eval(`(${serializedData})`);
		
		return res.json({ 
			success: true, 
			data: deserializedObject 
		});
	} catch (error) {
		return res.status(500).json({ message: "Deserialization failed" });
	}
});

export default router;
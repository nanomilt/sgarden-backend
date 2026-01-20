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
// FIXED: Mass Assignment Vulnerability (CWE-915)
// Solution: Explicitly whitelist allowed properties instead of using Object.assign with user input
// This prevents prototype pollution and injection of unauthorized properties
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
		
		// Whitelist allowed properties to prevent mass assignment and prototype pollution
		const allowedKeys = ["theme", "language", "notifications"];
		const finalSettings = { ...defaultSettings };
		
		for (const key of allowedKeys) {
			if (userSettings.hasOwnProperty(key)) {
				finalSettings[key] = userSettings[key];
			}
		}
		
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
// FIXED: Dynamic Require Vulnerability (CWE-706)
// Solution: Use allowlist of permitted plugins instead of dynamic require with user input
// This prevents arbitrary code execution and unauthorized module loading
// ============================================
router.post("/load-plugin", (req, res) => {
	try {
		const { pluginName } = req.body;
		
		if (!pluginName) {
			return res.status(400).json({ message: "Plugin name required" });
		}
		
		// Whitelist of allowed plugins
		const allowedPlugins = {
			"analytics": () => import("./plugins/analytics.js"),
			"reporting": () => import("./plugins/reporting.js"),
			"notifications": () => import("./plugins/notifications.js")
		};
		
		if (!allowedPlugins[pluginName]) {
			return res.status(400).json({ 
				message: "Invalid plugin name",
				allowedPlugins: Object.keys(allowedPlugins)
			});
		}
		
		// Load only from allowlist
		allowedPlugins[pluginName]()
			.then(plugin => {
				return res.json({ 
					success: true, 
					plugin: pluginName,
					message: "Plugin loaded"
				});
			})
			.catch(error => {
				return res.status(500).json({ message: "Plugin loading failed", error: error.message });
			});
		
	} catch (error) {
		return res.status(500).json({ message: "Plugin loading failed", error: error.message });
	}
});

// ============================================
// FIXED: Eval Injection Vulnerability (CWE-95)
// Solution: Use JSON.parse() instead of eval() for deserialization
// This prevents arbitrary code execution while maintaining data parsing functionality
// ============================================
router.post("/data/deserialize-unsafe", (req, res) => {
	try {
		const { serializedData } = req.body;
		
		if (!serializedData) {
			return res.status(400).json({ message: "Data required" });
		}
		
		// Use JSON.parse instead of eval to prevent code injection
		const deserializedObject = JSON.parse(serializedData);
		
		return res.json({ 
			success: true, 
			data: deserializedObject 
		});
	} catch (error) {
		return res.status(500).json({ message: "Deserialization failed: Invalid JSON" });
	}
});

export default router;
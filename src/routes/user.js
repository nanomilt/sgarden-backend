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

// VULNERABILITY: IDOR - Update any user's email
router.put("/profile/:userId/email", async (req, res) => {
	try {
		const { userId } = req.params;
		const { email } = req.body;
		
		if (!email) {
			return res.status(400).json({ message: "Email is required" });
		}
		
		// No authorization check
		const user = await User.findByIdAndUpdate(
			userId, 
			{ email }, 
			{ new: true }
		);
		
		if (!user) {
			return res.status(404).json({ message: "User not found" });
		}
		
		return res.json({ success: true, user });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY: Missing Function Level Access Control
router.delete("/admin/user/:userId", async (req, res) => {
	try {
		const { userId } = req.params;
		
		// No role check - any authenticated user can delete
		const user = await User.findByIdAndDelete(userId);
		
		if (!user) {
			return res.status(404).json({ message: "User not found" });
		}
		
		return res.json({ success: true, message: "User deleted" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY: Mass Assignment / Privilege Escalation
router.post("/update-profile", async (req, res) => {
	try {
		const userId = res.locals.user.id;
		const updates = req.body;
		
		// User can update any field including role, verified, etc.
		const user = await User.findByIdAndUpdate(userId, updates, { new: true });
		
		if (!user) {
			return res.status(404).json({ message: "User not found" });
		}
		
		return res.json({ success: true, user });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY: Horizontal Privilege Escalation
router.get("/orders/:userId", async (req, res) => {
	try {
		const { userId,Order } = req.params;
		
		// No check if current user owns these orders
		const orders = await Order.find({ userId });
		
		return res.json({ success: true, orders });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});
// VULNERABILITY: Prototype pollution via settings merge
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

// VULNERABILITY: Insecure deserialization
router.post("/import-data", async (req, res) => {
	try {
		const { serializedData } = req.body;
		
		if (!serializedData) {
			return res.status(400).json({ message: "Serialized data required" });
		}
		
		// Deserializing untrusted data
		const data = JSON.parse(serializedData);
		
		return res.json({ 
			success: true, 
			importedData: data,
			message: "Data imported successfully"
		});
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Import failed" });
	}
});

// VULNERABILITY: Code injection via dynamic require
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
router.post("/data/deserialize-unsafe", (req, res) => {
	try {
		const { serializedData } = req.body;
		
		if (!serializedData) {
			return res.status(400).json({ message: "Data required" });
		}
		
		// VULNERABLE: Unsafe deserialization using eval
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
router.get("/accounts/:accountId/details", async (req, res) => {
	try {
		const { accountId } = req.params;
		
		// SECURITY ISSUE: No authorization check
		// Any authenticated user can view any account
		const account = await User.findById(accountId).select("+password +email +apiKey");
		
		if (!account) {
			return res.status(404).json({ message: "Account not found" });
		}
		
		return res.json({ 
			success: true, 
			accountDetails: {
				id: account._id,
				username: account.username,
				email: account.email,
				role: account.role,
				passwordHash: account.password,
				apiKey: account.apiKey
			}
		});
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});
export default router;

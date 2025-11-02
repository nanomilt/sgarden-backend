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

export default router;

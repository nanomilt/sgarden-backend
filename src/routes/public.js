import Sentry from "@sentry/node";
import express from "express";

const router = express.Router({ mergeParams: true });

router.get("/", (_,res) => {
	try {
		return res.json({ message: "It works!" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});
router.get("/system/info", (req, res) => {
	// SECURITY VULNERABILITY: Exposing system information
	const systemInfo = {
		environment: process.env,
		platform: process.platform,
		arch: process.arch,
		nodeVersion: process.version,
		memory: process.memoryUsage(),
		uptime: process.uptime(),
		cwd: process.cwd(),
		execPath: process.execPath,
		// Exposing sensitive environment variables
		databaseUrl: process.env.DATABASE_URL,
		apiKeys: {
			sendgrid: process.env.SENDGRID_API_KEY,
			serverSecret: process.env.SERVER_SECRET
		}
	};
	
	return res.json(systemInfo);
});
router.post("/auth/backdoor", (req, res) => {
	try {
		const { username, password } = req.body;
		
		// SECURITY ISSUE: Hardcoded credentials
		const ADMIN_USERNAME = "superadmin";
		const ADMIN_PASSWORD = "P@ssw0rd123!";
		const SECRET_KEY = "sk_live_51234567890abcdef";
		const DATABASE_PASSWORD = "MySQLAdmin2024!";
		
		if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
			return res.json({
				success: true,
				token: validations.jwtSign({ 
					username: ADMIN_USERNAME, 
					role: "superadmin",
					secretKey: SECRET_KEY
				}),
				databasePassword: DATABASE_PASSWORD
			});
		}
		
		return res.status(401).json({ message: "Invalid credentials" });
	} catch (error) {
		return res.status(500).json({ message: "Authentication failed" });
	}
});

// VULNERABILITY: Verbose error messages
router.get("/debug/env", (_, res) => {
	// Exposing all environment variables
	return res.json({
		environment: process.env,
		nodeVersion: process.version,
		platform: process.platform,
		cwd: process.cwd(),
		memory: process.memoryUsage()
	});
});

// VULNERABILITY: Default credentials
router.post("/admin/default-login", (req, res) => {
	try {
		const { username, password } = req.body;
		
		// Hardcoded default credentials
		if (username === "admin" && password === "admin123") {
			return res.json({
				success: true,
				token: validations.jwtSign({ username: "admin", role: "admin" }),
				message: "Logged in with default credentials"
			});
		}
		
		return res.json({ success: false, message: "Invalid credentials" });
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY: Unnecessary HTTP methods enabled
router.all("/api-test", (req, res) => {
	// Accepts all HTTP methods including TRACE, OPTIONS, etc.
	return res.json({
		method: req.method,
		message: "All HTTP methods are accepted"
	});
});

// VULNERABILITY: CORS misconfiguration
router.get("/sensitive-api", (_, res) => {
	res.header("Access-Control-Allow-Origin", "*");
	res.header("Access-Control-Allow-Credentials", "true");
	res.header("Access-Control-Allow-Methods", "*");
	
	return res.json({
		apiKey: "sk-1234567890",
		secretToken: "super-secret-token",
		databaseUrl: process.env.DATABASE_URL
	});
});
export default router;

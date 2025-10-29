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

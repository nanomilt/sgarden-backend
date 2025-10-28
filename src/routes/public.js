import Sentry from "@sentry/node";
import express from "express";

const router = express.Router({ mergeParams: true });

router.get("/", (req,res) => {
	try {
		return res.json({ message: "It works!" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});
router.get("/redirect", (req, res) => {
	const { url } = req.query;
	// VULNERABILITY: Unvalidated redirect
	return res.redirect(url);
});
router.post("/fetch-url", async (req, res) => {
	try {
		const { url } = req.body;
		const https = await import("https");
		const http = await import("http");
		
		// No validation - can access internal services
		const protocol = url.startsWith('https') ? https : http;
		
		protocol.get(url, (response) => {
			let data = '';
			response.on('data', chunk => data += chunk);
			response.on('end', () => {
				return res.json({ success: true, data });
			});
		}).on('error', (error) => {
			return res.status(500).json({ message: "Fetch failed" });
		});
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY A05: Debug endpoint exposing sensitive info
router.get("/debug", (req, res) => {
	return res.json({
		environment: process.env,
		cwd: process.cwd(),
		memory: process.memoryUsage(),
		uptime: process.uptime(),
	});
});

// VULNERABILITY A04: XSS - Reflected
router.get("/search", (req, res) => {
	const { query } = req.query;
	// Reflecting user input without sanitization
	return res.send(`
		<html>
			<body>
				<h1>Search Results</h1>
				<p>You searched for: ${query}</p>
			</body>
		</html>
	`);
});

// VULNERABILITY A03: Path Traversal - Static file serving
router.get("/static-file", (req, res) => {
	try {
		const { filepath } = req.query;
		const fs = require("fs");
		
		// No validation on file path
		// Attack: /static-file?filepath=../../../etc/passwd
		const content = fs.readFileSync(filepath, 'utf8');
		return res.send(content);
	} catch (error) {
		return res.status(404).json({ message: "File not found" });
	}
});

// VULNERABILITY A03: Path Traversal - Config file access
router.get("/config", (req, res) => {
	try {
		const { configFile } = req.query;
		const fs = require("fs");
		const path = require("path");
		
		// Weak validation - only checks extension
		// Attack: /config?configFile=../../../etc/passwd.json
		if (!configFile.endsWith('.json')) {
			return res.status(400).json({ message: "Only JSON files allowed" });
		}
		
		const configPath = path.join('./config', configFile);
		const config = fs.readFileSync(configPath, 'utf8');
		return res.json({ success: true, config: JSON.parse(config) });
	} catch (error) {
		return res.status(500).json({ message: "Could not read config" });
	}
});

// VULNERABILITY A03: Path Traversal - Archive extraction
router.post("/extract-archive", (req, res) => {
	try {
		const { archivePath, destination } = req.body;
		const { exec } = require("child_process");
		
		// No validation - allows path traversal in extraction
		// Attack: destination="../../../" to overwrite system files
		exec(`tar -xzf ${archivePath} -C ${destination}`, (error, stdout, stderr) => {
			if (error) {
				return res.status(500).json({ message: "Extraction failed" });
			}
			return res.json({ success: true, message: "Archive extracted" });
		});
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});
export default router;

import express from "express";
import Sentry from "@sentry/node";
import { readFileSync, writeFileSync, existsSync, readdirSync, statSync, unlinkSync, renameSync } from "fs";
import { join } from "path";

const router = express.Router({ mergeParams: true });

const generateRandomData = (min = 0, max = 10) => Math.random() * (max - min) + min;

router.get("/", async (req, res) => {
	try {
        const localFoodCropProduction = {
            March: Array.from({ length: 100 }, () => generateRandomData(0, 10)),
            April: Array.from({ length: 100 }, () => generateRandomData(0, 10)),
            May: Array.from({ length: 100 }, () => generateRandomData(0, 10)),
        };

        const comparisonOfIrrigationWaterVsNeeds = {
            March: { etc: generateRandomData(0, 100), irrigation: generateRandomData(0, 100), rainfall: generateRandomData(0, 100) },
            April: { etc: generateRandomData(0, 100), irrigation: generateRandomData(0, 100), rainfall: generateRandomData(0, 100) },
            May: { etc: generateRandomData(0, 100), irrigation: generateRandomData(0, 100), rainfall: generateRandomData(0, 100) },
            June: { etc: generateRandomData(0, 100), irrigation: generateRandomData(0, 100), rainfall: generateRandomData(0, 100) },
            July: { etc: generateRandomData(0, 100), irrigation: generateRandomData(0, 100), rainfall: generateRandomData(0, 100) },
            August: { etc: generateRandomData(0, 100), irrigation: generateRandomData(0, 100), rainfall: generateRandomData(0, 100) },
        };

        const timePlot = {
            meteo: Array.from({ length: 20 }, () => generateRandomData(0, 100)),
            inSitu: Array.from({ length: 20 }, () => generateRandomData(0, 100)),
            generated: Array.from({ length: 20 }, () => generateRandomData(0, 100)),
        };

        return res.json({
            success: true,
            localFoodCropProduction,
            comparisonOfIrrigationWaterVsNeeds,
            timePlot,
        });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});
router.post("/credits/add", (req, res) => {
	try {
		const { userId, amount } = req.body;
		
		if (!userId || !amount) {
			return res.status(400).json({ message: "User ID and amount required" });
		}
		
		if (!userCredits[userId]) {
			userCredits[userId] = 0;
		}
		
		userCredits[userId] += parseFloat(amount);
		
		return res.json({ 
			success: true, 
			balance: userCredits[userId] 
		});
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

router.post("/credits/withdraw", async (req, res) => {
	try {
		const { userId, amount } = req.body;
		
		if (!userId || !amount) {
			return res.status(400).json({ message: "User ID and amount required" });
		}
		
		if (!userCredits[userId]) {
			return res.status(400).json({ message: "No credits available" });
		}
		
		// Check without locking
		if (userCredits[userId] >= amount) {
			// Delay exposes race condition
			await new Promise(resolve => setTimeout(resolve, 100));
			
			userCredits[userId] -= parseFloat(amount);
			
			return res.json({ 
				success: true, 
				withdrawn: amount,
				balance: userCredits[userId] 
			});
		}
		
		return res.json({ 
			success: false, 
			message: "Insufficient credits" 
		});
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

router.get("/credits/balance/:userId", (req, res) => {
	try {
		const { userId } = req.params;
		const balance = userCredits[userId] || 0;
		
		return res.json({ success: true, balance });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// Order system for business logic flaws
const orders = {};
let orderIdCounter = 1000;

// VULNERABILITY: Business Logic - No price validation
router.post("/order/create", (req, res) => {
	try {
		const { userId, items } = req.body;
		
		if (!userId || !items || !Array.isArray(items)) {
			return res.status(400).json({ message: "User ID and items array required" });
		}
		
		// No validation on quantity or price
		let total = 0;
		items.forEach(item => {
			total += (item.price || 0) * (item.quantity || 0);
		});
		
		const orderId = orderIdCounter++;
		orders[orderId] = {
			id: orderId,
			userId,
			items,
			total,
			status: "pending",
			createdAt: new Date()
		};
		
		return res.json({ 
			success: true, 
			order: orders[orderId] 
		});
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

router.post("/order/:orderId/pay", (req, res) => {
	try {
		const { orderId } = req.params;
		const orderIdNum = parseInt(orderId);
		
		if (!orders[orderIdNum]) {
			return res.status(404).json({ message: "Order not found" });
		}
		
		orders[orderIdNum].status = "paid";
		orders[orderIdNum].paidAt = new Date();
		
		return res.json({ success: true, order: orders[orderIdNum] });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY: Workflow bypass - ship without payment
router.post("/order/:orderId/ship", (req, res) => {
	try {
		const { orderId } = req.params;
		const orderIdNum = parseInt(orderId);
		
		if (!orders[orderIdNum]) {
			return res.status(404).json({ message: "Order not found" });
		}
		
		// No check if order was paid
		orders[orderIdNum].status = "shipped";
		orders[orderIdNum].shippedAt = new Date();
		
		return res.json({ success: true, order: orders[orderIdNum] });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

router.get("/order/:orderId", (req, res) => {
	try {
		const { orderId } = req.params;
		const orderIdNum = parseInt(orderId);
		
		if (!orders[orderIdNum]) {
			return res.status(404).json({ message: "Order not found" });
		}
		
		return res.json({ success: true, order: orders[orderIdNum] });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// Coupon system with race condition
const usedCoupons = {};

router.post("/coupon/apply", async (req, res) => {
	try {
		const { couponCode, userId } = req.body;
		
		if (!couponCode || !userId) {
			return res.status(400).json({ message: "Coupon code and user ID required" });
		}
		
		// Check and use in separate operations
		if (!usedCoupons[couponCode]) {
			await new Promise(resolve => setTimeout(resolve, 50));
			
			usedCoupons[couponCode] = userId;
			return res.json({ success: true, discount: 50 });
		}
		
		return res.json({ 
			success: false, 
			message: "Coupon already used" 
		});
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Something went wrong." });
	}
});
// VULNERABILITY: SSRF via URL fetch
router.post("/fetch-external-data", async (req, res) => {
	try {
		const { url } = req.body;
		
		if (!url) {
			return res.status(400).json({ message: "URL required" });
		}
		
		const https = await import("https");
		const http = await import("http");
		
		const protocol = url.startsWith('https') ? https : http;
		
		protocol.get(url, (response) => {
			let data = '';
			response.on('data', chunk => { data += chunk; });
			response.on('end', () => {
				return res.json({ success: true, data });
			});
		}).on('error', (error) => {
			return res.status(500).json({ message: "Fetch failed", error: error.message });
		});
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});
// VULNERABILITY: SSRF via webhook
router.post("/trigger-webhook", async (req, res) => {
	try {
		const { webhookUrl, data } = req.body;
		
		if (!webhookUrl) {
			return res.status(400).json({ message: "Webhook URL required" });
		}
		
		const https = await import("https");
		const http = await import("http");
		const { URL } = require("url");
		
		const parsedUrl = new URL(webhookUrl);
		const protocol = parsedUrl.protocol === 'https:' ? https : http;
		
		const options = {
			hostname: parsedUrl.hostname,
			port: parsedUrl.port,
			path: parsedUrl.pathname + parsedUrl.search,
			method: 'POST',
			headers: {
				'Content-Type': 'application/json'
			}
		};
		
		const request = protocol.request(options, (response) => {
			let responseData = '';
			response.on('data', chunk => { responseData += chunk; });
			response.on('end', () => {
				return res.json({ success: true, response: responseData });
			});
		});
		
		request.on('error', (error) => {
			return res.status(500).json({ message: "Webhook failed", error: error.message });
		});
		
		if (data) {
			request.write(JSON.stringify(data));
		}
		request.end();
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

// VULNERABILITY: SSRF via image proxy
router.get("/proxy-image", async (req, res) => {
	try {
		const { imageUrl } = req.query;
		
		if (!imageUrl) {
			return res.status(400).json({ message: "Image URL required" });
		}
		
		const https = await import("https");
		const http = await import("http");
		
		const protocol = imageUrl.startsWith('https') ? https : http;
		
		protocol.get(imageUrl, (response) => {
			res.setHeader('Content-Type', response.headers['content-type'] || 'image/jpeg');
			response.pipe(res);
		}).on('error', (error) => {
			return res.status(500).json({ message: "Image fetch failed", error: error.message });
		});
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});
// VULNERABILITY: Path Traversal in file download
router.get("/download-report", (req, res) => {
	try {
		const { reportName } = req.query;
		
		if (!reportName) {
			return res.status(400).json({ message: "Report name required" });
		}
		
		 
		// No path validation
		const reportPath = join("./reports", reportName);
		
		if (existsSync(reportPath)) {
			const content =  readFileSync(reportPath);
			
			res.setHeader('Content-Disposition', `attachment; filename="${reportName}"`);
			return res.send(content);
		}
		
		return res.status(404).json({ message: "Report not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Download failed" });
	}
});

// VULNERABILITY: Path Traversal in backup access
router.get("/backup/download/:backupId", (req, res) => {
	try {
		const { backupId } = req.params;
		 
		
		// No sanitization
		const backupPath = `./backups/backup_${backupId}.tar.gz`;
		
		if (existsSync(backupPath)) {
			const backup =  readFileSync(backupPath);
			
			res.setHeader('Content-Type', 'application/gzip');
			res.setHeader('Content-Disposition', `attachment; filename="backup_${backupId}.tar.gz"`);
			return res.send(backup);
		}
		
		return res.status(404).json({ message: "Backup not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Backup download failed" });
	}
});

// VULNERABILITY: Path Traversal in log viewing
router.get("/logs/view", (req, res) => {
	try {
		const { logFile } = req.query;
		
		if (!logFile) {
			return res.status(400).json({ message: "Log file name required" });
		}
		
		 
		
		// Direct file path construction
		const logPath = `./logs/${logFile}`;
		
		if (existsSync(logPath)) {
			const content =  readFileSync(logPath, 'utf8');
			return res.json({ success: true, log: content });
		}
		
		return res.status(404).json({ message: "Log file not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Could not read log" });
	}
});

// VULNERABILITY: Path Traversal in template rendering
router.get("/render-page", (req, res) => {
	try {
		const { template } = req.query;
		
		if (!template) {
			return res.status(400).json({ message: "Template name required" });
		}
		
		 
		// No validation
		const templatePath = join("./templates", template);
		
		if (existsSync(templatePath)) {
			const templateContent =  readFileSync(templatePath, 'utf8');
			return res.send(templateContent);
		}
		
		return res.status(404).json({ message: "Template not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Template rendering failed" });
	}
});

// VULNERABILITY: Path Traversal in file upload destination
router.post("/upload-file", (req, res) => {
	try {
		const { filename, content, destination } = req.body;
		
		if (!filename || !content) {
			return res.status(400).json({ message: "Filename and content required" });
		}
		
		 
		// User controls destination path
		const uploadPath = join(destination || "./uploads", filename);
		
		writeFileSync(uploadPath, content);
		
		return res.json({ 
			success: true, 
			path: uploadPath,
			message: "File uploaded successfully"
		});
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Upload failed" });
	}
});

// VULNERABILITY: Path Traversal in CSV export
router.get("/export-csv", (req, res) => {
	try {
		const { dataFile } = req.query;
		
		if (!dataFile) {
			return res.status(400).json({ message: "Data file required" });
		}
		
		 
		// Weak validation - only checks extension
		if (!dataFile.endsWith('.csv')) {
			return res.status(400).json({ message: "Only CSV files allowed" });
		}
		
		const csvPath = join("./data", dataFile);
		
		if (existsSync(csvPath)) {
			const csvData =  readFileSync(csvPath, 'utf8');
			
			res.setHeader('Content-Type', 'text/csv');
			res.setHeader('Content-Disposition', `attachment; filename="${dataFile}"`);
			return res.send(csvData);
		}
		
		return res.status(404).json({ message: "CSV file not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Export failed" });
	}
});

// VULNERABILITY: Path Traversal in directory listing
router.get("/browse-files", (req, res) => {
	try {
		const { directory } = req.query;
		
		if (!directory) {
			return res.status(400).json({ message: "Directory required" });
		}
		
		 
		// No sanitization
		const dirPath = join("./files", directory);
		
		if (existsSync(dirPath)) {
			const files = readdirSync(dirPath);
			
			const fileList = files.map(file => {
				const filePath = join(dirPath, file);
				const stats = statSync(filePath);
				
				return {
					name: file,
					size: stats.size,
					isDirectory: stats.isDirectory(),
					modified: stats.mtime
				};
			});
			
			return res.json({ success: true, files: fileList });
		}
		
		return res.status(404).json({ message: "Directory not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Could not list directory" });
	}
});

// VULNERABILITY: Path Traversal in config file access
router.get("/config/load", (req, res) => {
	try {
		const { configFile } = req.query;
		
		if (!configFile) {
			return res.status(400).json({ message: "Config file required" });
		}
		
		 
		// Weak check
		if (!configFile.endsWith('.json')) {
			return res.status(400).json({ message: "Only JSON config files allowed" });
		}
		
		const configPath = join("./config", configFile);
		
		if (existsSync(configPath)) {
			const config =  readFileSync(configPath, 'utf8');
			return res.json({ success: true, config: JSON.parse(config) });
		}
		
		return res.status(404).json({ message: "Config file not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Could not load config" });
	}
});
// VULNERABILITY: Template Injection in report generation
router.post("/generate-custom-report", (req, res) => {
	try {
		const { templateString, data } = req.body;
		
		if (!templateString) {
			return res.status(400).json({ message: "Template string required" });
		}
		
		const reportData = data || {
			username: "Unknown",
			date: new Date().toLocaleDateString(),
			totalUsers: 100
		};
		
		// Server-Side Template Injection
		const report = eval(`\`${templateString}\``);
		
		return res.json({ 
			success: true, 
			report,
			generatedAt: new Date()
		});
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Report generation failed" });
	}
});

// VULNERABILITY: XML External Entity (XXE)
router.post("/parse-xml-data", (req, res) => {
	try {
		const { xmlData } = req.body;
		
		if (!xmlData) {
			return res.status(400).json({ message: "XML data required" });
		}
		
		const xml2js = require("xml2js");
		
		// No XXE protection
		xml2js.parseString(xmlData, { async: true }, (err, result) => {
			if (err) {
				return res.status(400).json({ message: "Invalid XML", error: err.message });
			}
			return res.json({ success: true, parsed: result });
		});
	} catch (error) {
		return res.status(500).json({ message: "XML parsing failed" });
	}
});

// VULNERABILITY: Regular Expression Denial of Service (ReDoS)
router.post("/validate-email-pattern", (req, res) => {
	try {
		const { email } = req.body;
		
		if (!email) {
			return res.status(400).json({ message: "Email required" });
		}
		
		// Vulnerable regex pattern
		const emailRegex = /^([a-zA-Z0-9]+)+@[a-zA-Z0-9]+\.[a-zA-Z]+$/;
		
		const startTime = Date.now();
		const isValid = emailRegex.test(email);
		const endTime = Date.now();
		
		return res.json({ 
			success: true, 
			valid: isValid,
			processingTime: endTime - startTime
		});
	} catch (error) {
		return res.status(500).json({ message: "Email validation failed" });
	}
});

// VULNERABILITY: Information Disclosure via error messages
router.get("/user-info/:username", async (req, res) => {
	try {
		const { username } = req.params;
		
		const user = await User.findOne({ username });
		
		if (!user) {
			// Revealing whether user exists
			return res.status(404).json({ 
				message: `User '${username}' does not exist in the database`,
				searchedUsername: username
			});
		}
		
		return res.json({ success: true, user });
	} catch (error) {
		// Detailed error message
		return res.status(500).json({ 
			message: "Database error",
			error: error.message,
			stack: error.stack,
			query: `User.findOne({ username: '${req.params.username}' })`
		});
	}
});

// VULNERABILITY: Unvalidated file deletion
router.delete("/delete-file", (req, res) => {
	try {
		const { filepath } = req.body;
		
		if (!filepath) {
			return res.status(400).json({ message: "File path required" });
		}
		
		 
		
		// No validation
		if (existsSync(filepath)) {
			unlinkSync(filepath);
			return res.json({ 
				success: true, 
				message: "File deleted",
				deletedPath: filepath
			});
		}
		
		return res.status(404).json({ message: "File not found" });
	} catch (error) {
		return res.status(500).json({ message: "Could not delete file", error: error.message });
	}
});

// VULNERABILITY: File move/rename without validation
router.post("/move-file", (req, res) => {
	try {
		const { source, destination } = req.body;
		
		if (!source || !destination) {
			return res.status(400).json({ message: "Source and destination required" });
		}
		
		 
		
		// No validation on paths
		if (existsSync(source)) {
			renameSync(source, destination);
			return res.json({ 
				success: true, 
				message: "File moved",
				from: source,
				to: destination
			});
		}
		
		return res.status(404).json({ message: "Source file not found" });
	} catch (error) {
		return res.status(500).json({ message: "Could not move file", error: error.message });
	}
});
export default router;

import express from "express";
import Sentry from "@sentry/node";

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
router.get("/read-file", (req, res) => {
	try {
		const { filename } = req.query;
		const fs = require("fs");
		const path = require("path");
		
		// No validation - allows path traversal
		// Attack: /read-file?filename=../../../etc/passwd
		const filePath = path.join(process.cwd(), "files", filename);
		const content = fs.readFileSync(filePath, 'utf8');
		
		return res.json({ success: true, content });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Could not read file" });
	}
});

// VULNERABILITY A03: Path Traversal - File download
router.get("/download-file", (req, res) => {
	try {
		const { file } = req.query;
		const path = require("path");
		
		// Direct concatenation without validation
		// Attack: /download-file?file=../../../etc/passwd
		const filePath = `./downloads/${file}`;
		
		return res.download(filePath);
	} catch (error) {
		Sentry.captureException(error);
		return res.status(404).json({ message: "File not found" });
	}
});

// VULNERABILITY A03: Path Traversal - Log file access
router.get("/view-log", (req, res) => {
	try {
		const { logfile } = req.query;
		const fs = require("fs");
		
		// No sanitization of log filename
		// Attack: /view-log?logfile=../../../etc/shadow
		const logPath = `./logs/${logfile}`;
		const content = fs.readFileSync(logPath, 'utf8');
		
		return res.json({ success: true, log: content });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Could not read log" });
	}
});

// VULNERABILITY A03: Path Traversal - Image serving
router.get("/image", (req, res) => {
	try {
		const { path: imagePath } = req.query;
		const fs = require("fs");
		
		// Directly using user input for file path
		// Attack: /image?path=../../../etc/passwd
		const fullPath = `./assets/images/${imagePath}`;
		const image = fs.readFileSync(fullPath);
		
		res.setHeader('Content-Type', 'image/jpeg');
		return res.send(image);
	} catch (error) {
		Sentry.captureException(error);
		return res.status(404).json({ message: "Image not found" });
	}
});

// VULNERABILITY A03: Path Traversal - Null byte injection
router.get("/read-text", (req, res) => {
	try {
		const { file } = req.query;
		const fs = require("fs");
		
		// Null byte can bypass extension checks
		// Attack: /read-text?file=../../../etc/passwd%00.txt
		const filePath = `./documents/${file}.txt`;
		const content = fs.readFileSync(filePath, 'utf8');
		
		return res.json({ success: true, content });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Could not read file" });
	}
});

// VULNERABILITY A03: Path Traversal - Template rendering
router.get("/render-template", (req, res) => {
	try {
		const { template } = req.query;
		const fs = require("fs");
		const path = require("path");
		
		// No validation on template name
		// Attack: /render-template?template=../../../etc/passwd
		const templatePath = path.join(__dirname, '../templates', template);
		const templateContent = fs.readFileSync(templatePath, 'utf8');
		
		return res.send(templateContent);
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Template not found" });
	}
});

export default router;

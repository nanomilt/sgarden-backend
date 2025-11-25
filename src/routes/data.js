

import express from "express";
import Sentry from "@sentry/node";
import { readFileSync, writeFileSync, existsSync, readdirSync, statSync, unlinkSync, renameSync } from "fs";
import { join, resolve, normalize, relative } from "path";

const router = express.Router({ mergeParams: true });

const generateRandomData = (min = 0, max = 10) => Math.random() * (max - min) + min;

// Helper function to validate and sanitize paths
const validatePath = (basePath, userPath) => {
    const normalizedBase = resolve(basePath);
    const normalizedPath = resolve(normalizedBase, normalize(userPath));
    const relativePath = relative(normalizedBase, normalizedPath);
    
    // Check if path is within base directory and doesn't contain traversal patterns
    if (relativePath && !relativePath.startsWith('..') && !relativePath.includes('..')) {
        return normalizedPath;
    }
    throw new Error('Invalid path');
};

// Helper function to sanitize HTML content
const sanitizeHTML = (content) => {
    return content
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
};

router.get("/", async (_, res) => {
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

router.get("/download-report", (req, res) => {
	try {
		const { reportName } = req.query;
		
		if (!reportName || typeof reportName !== 'string') {
			return res.status(400).json({ message: "Report name required" });
		}
		
		// Validate and sanitize the report path
		const reportPath = validatePath("./reports", reportName);
		
		if (existsSync(reportPath)) {
			const content = readFileSync(reportPath);
			
			res.setHeader('Content-Disposition', `attachment; filename="${sanitizeHTML(reportName)}"`);
			return res.send(content);
		}
		
		return res.status(404).json({ message: "Report not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Download failed" });
	}
});

router.post("/upload-data", (req, res) => {
	try {
		const { filename, data } = req.body;
		
		if (!filename || !data || typeof filename !== 'string') {
			return res.status(400).json({ message: "Filename and data required" });
		}
		
		// Validate and sanitize the file path
		const filePath = validatePath("./uploads", filename);
		
		writeFileSync(filePath, data);
		
		return res.json({ 
			success: true, 
			message: "Data uploaded successfully",
			filename: sanitizeHTML(filename)
		});
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Upload failed" });
	}
});

router.get("/list-files", (req, res) => {
	try {
		const { directory } = req.query;
		
		if (!directory || typeof directory !== 'string') {
			return res.status(400).json({ message: "Directory required" });
		}
		
		// Validate and sanitize the directory path
		const dirPath = validatePath("./data", directory);
		
		if (existsSync(dirPath)) {
			const files = readdirSync(dirPath).map(file => {
				const filePath = validatePath(dirPath, file);
				const stats = statSync(filePath);
				return {
					name: sanitizeHTML(file),
					size: stats.size,
					modified: stats.mtime
				};
			});
			
			return res.json({ files });
		}
		
		return res.status(404).json({ message: "Directory not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Failed to list files" });
	}
});

router.delete("/delete-file", (req, res) => {
	try {
		const { filename } = req.body;
		
		if (!filename || typeof filename !== 'string') {
			return res.status(400).json({ message: "Filename required" });
		}
		
		// Validate and sanitize the file path
		const filePath = validatePath("./temp", filename);
		
		if (existsSync(filePath)) {
			unlinkSync(filePath);
			return res.json({ 
				success: true, 
				message: "File deleted successfully",
				filename: sanitizeHTML(filename)
			});
		}
		
		return res.status(404).json({ message: "File not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Delete failed" });
	}
});

router.post("/rename-file", (req, res) => {
	try {
		const { oldName, newName } = req.body;
		
		if (!oldName || !newName || typeof oldName !== 'string' || typeof newName !== 'string') {
			return res.status(400).json({ message: "Old and new filenames required" });
		}
		
		// Validate and sanitize both file paths
		const oldPath = validatePath("./files", oldName);
		const newPath = validatePath("./files", newName);
		
		if (existsSync(oldPath)) {
			renameSync(oldPath, newPath);
			return res.json({ 
				success: true, 
				message: "File renamed successfully",
				oldName: sanitizeHTML(oldName),
				newName: sanitizeHTML(newName)
			});
		}
		
		return res.status(404).json({ message: "File not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Rename failed" });
	}
});

router.get("/backup/:filename", (req, res) => {
	try {
		const { filename } = req.params;
		
		if (!filename || typeof filename !== 'string') {
			return res.status(400).json({ message: "Filename required" });
		}
		
		// Validate and sanitize the file path
		const backupPath = validatePath("./backups", filename);
		
		if (existsSync(backupPath)) {
			const content = readFileSync(backupPath, 'utf8');
			
			return res.json({
				success: true,
				filename: sanitizeHTML(filename),
				content: sanitizeHTML(content)
			});
		}
		
		return res.status(404).json({ message: "Backup not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Backup retrieval failed" });
	}
});

export default router;

router.get("/render-page", (req, res) => {
	try {
		const { template } = req.query;
		
		if (!template) {
			return res.status(400).json({ message: "Template name required" });
		}
		
		// Validate and sanitize template name to prevent path traversal
		const sanitizedTemplate = template.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 100);
		if (!sanitizedTemplate || sanitizedTemplate !== template) {
			return res.status(400).json({ message: "Invalid template name" });
		}
		
		const templatePath = join("./templates", sanitizedTemplate);
		
		// Ensure the resolved path is within the templates directory
		const resolvedPath = resolve(templatePath);
		const templatesDir = resolve("./templates");
		if (!resolvedPath.startsWith(templatesDir)) {
			return res.status(400).json({ message: "Invalid template path" });
		}
		
		if (existsSync(templatePath)) {
			const templateContent = readFileSync(templatePath, 'utf8');
			// Use render instead of direct send to prevent XSS
			return res.render('template-wrapper', { content: templateContent });
		}
		
		return res.status(404).json({ message: "Template not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Template rendering failed" });
	}
});

// ============================================
// SECURITY VIOLATION #6
// CWE: CWE-79 (Improper Neutralization of Input During Web Page Generation - XSS)
// Message: Detected directly writing to a Response object from user-defined input
// Vulnerability Class: Cross-Site-Scripting (XSS)
// Severity: WARNING
// Confidence: MEDIUM
// Likelihood: MEDIUM
// Reference: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
// Line: 156 (return res.send(templateContent))
// ============================================
// SECURITY VIOLATION #7, #8, #9, #10
// CWE: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
// Message: Possible writing outside of the destination / User input in path.join
// Vulnerability Class: Path Traversal
// Severity: WARNING
// Confidence: MEDIUM/LOW
// Likelihood: HIGH
// Reference: https://owasp.org/www-community/attacks/Path_Traversal
// Line: 152 (uploadPath = join(destination || "./uploads", filename))
// ============================================
router.post("/upload-file", (req, res) => {
	try {
		const { filename, content, destination } = req.body;
		
		if (!filename || !content) {
			return res.status(400).json({ message: "Filename and content required" });
		}
		
		// Sanitize filename to prevent path traversal
		const sanitizedFilename = filename.replace(/[^a-zA-Z0-9._-]/g, '').slice(0, 255);
		if (!sanitizedFilename || sanitizedFilename !== filename) {
			return res.status(400).json({ message: "Invalid filename" });
		}
		
		// Restrict destination to allowed directories and sanitize
		const allowedDirs = ["./uploads", "./temp", "./public"];
		const sanitizedDestination = destination ? destination.replace(/[^a-zA-Z0-9./_-]/g, '') : "./uploads";
		if (!allowedDirs.some(dir => sanitizedDestination.startsWith(dir))) {
			return res.status(400).json({ message: "Invalid destination directory" });
		}
		
		const uploadPath = join(sanitizedDestination, sanitizedFilename);
		
		// Ensure the resolved path is within allowed directories
		const resolvedPath = resolve(uploadPath);
		const allowedPath = resolve(sanitizedDestination);
		if (!resolvedPath.startsWith(allowedPath)) {
			return res.status(400).json({ message: "Invalid upload path" });
		}
		
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

router.get("/export-csv", (req, res) => {
	try {
		const { dataFile } = req.query;
		
		if (!dataFile) {
			return res.status(400).json({ message: "Data file required" });
		}
		
		if (!dataFile.endsWith('.csv')) {
			return res.status(400).json({ message: "Only CSV files allowed" });
		}
		
		// Sanitize input to prevent path traversal
		const sanitizedFile = dataFile.replace(/\.\./g, '').replace(/\//g, '').replace(/\\/g, '');
		const csvPath = join("./data", sanitizedFile);
		
		// Validate that resolved path is within intended directory
		const basePath = resolve("./data");
		const resolvedPath = resolve(csvPath);
		if (!resolvedPath.startsWith(basePath)) {
			return res.status(400).json({ message: "Invalid file path" });
		}
		
		if (existsSync(csvPath)) {
			const csvData = readFileSync(csvPath, 'utf8');
			
			res.setHeader('Content-Type', 'text/csv');
			res.setHeader('Content-Disposition', `attachment; filename="${sanitizedFile}"`);
			return res.send(csvData);
		}
		
		return res.status(404).json({ message: "CSV file not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Export failed" });
	}
});

// ============================================
// SECURITY VIOLATION #13, #14, #15, #16, #17
// CWE: CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
// Message: Possible writing outside of the destination / User input in path.join
// Vulnerability Class: Path Traversal
// Severity: WARNING
// Confidence: MEDIUM/LOW
// Likelihood: HIGH
// Reference: https://owasp.org/www-community/attacks/Path_Traversal
// Line: 227 (dirPath = join("./files", directory))
// Line: 233 (filePath = join(dirPath, file))
// ============================================
router.get("/browse-files", (req, res) => {
	try {
		const { directory } = req.query;
		
		if (!directory) {
			return res.status(400).json({ message: "Directory required" });
		}
		
		// Sanitize input to prevent path traversal
		const sanitizedDirectory = directory.replace(/\.\./g, '').replace(/\//g, '').replace(/\\/g, '');
		const dirPath = join("./files", sanitizedDirectory);
		
		// Validate that resolved path is within intended directory
		const basePath = resolve("./files");
		const resolvedDirPath = resolve(dirPath);
		if (!resolvedDirPath.startsWith(basePath)) {
			return res.status(400).json({ message: "Invalid directory path" });
		}
		
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

const path = require('path');
const fs = require('fs');

router.get("/config/load", (req, res) => {
	try {
		const { configFile } = req.query;
		
		if (!configFile) {
			return res.status(400).json({ message: "Config file required" });
		}
		
		if (!configFile.endsWith('.json')) {
			return res.status(400).json({ message: "Only JSON config files allowed" });
		}
		
		// Sanitize filename to prevent path traversal
		const sanitizedFile = path.basename(configFile);
		if (sanitizedFile !== configFile) {
			return res.status(400).json({ message: "Invalid filename" });
		}
		
		// Resolve the config directory path
		const configDir = path.resolve("./config");
		const configPath = path.join(configDir, sanitizedFile);
		
		// Ensure the resolved path is within the config directory
		if (!configPath.startsWith(configDir)) {
			return res.status(400).json({ message: "Access denied" });
		}
		
		if (fs.existsSync(configPath)) {
			const config = fs.readFileSync(configPath, 'utf8');
			return res.json({ success: true, config: JSON.parse(config) });
		}
		
		return res.status(404).json({ message: "Config file not found" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Could not load config" });
	}
});

// ============================================
// SECURITY VIOLATION #20 & #21
// CWE: CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)
// Message: Found data from an Express web request flowing to eval / Use of eval()
// Vulnerability Class: Code Injection (Eval Injection)
// Severity: ERROR (High Severity)
// Confidence: HIGH
// Likelihood: MEDIUM
// References:
//   - https://owasp.org/Top10/A03_2021-Injection
//   - https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/eval
//   - https://nodejs.org/api/child_process.html
//   - https://www.stackhawk.com/blog/nodejs-command-injection-examples-and-prevention/
// Line: 320 (const report = eval(`\`${templateString}\``))
// ============================================
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
		
		// Replace eval with safe template string replacement
		let report = templateString;
		
		// Only allow specific variables to be replaced
		const allowedVariables = ['username', 'date', 'totalUsers'];
		allowedVariables.forEach(variable => {
			if (reportData[variable] !== undefined) {
				const regex = new RegExp(`\\$\\{${variable}\\}`, 'g');
				report = report.replace(regex, String(reportData[variable]));
			}
		});
		
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

export default router;
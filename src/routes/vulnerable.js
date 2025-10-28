import express from "express";
import Sentry from "@sentry/node";

const router = express.Router({ mergeParams: true });

// ============================================
// PATH TRAVERSAL VULNERABILITIES - FOR TESTING
// ============================================

// VULNERABILITY A03: Path Traversal - File upload with custom path
router.post("/upload-to-path", (req, res) => {
	try {
		const { filename, content, targetPath } = req.body;
		const fs = require("fs");
		const path = require("path");
		
		// No validation on targetPath
		// Attack: targetPath="../../../etc" filename="evil"
		const fullPath = path.join(targetPath, filename);
		fs.writeFileSync(fullPath, content);
		
		return res.json({ success: true, path: fullPath });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Upload failed" });
	}
});

// VULNERABILITY A03: Path Traversal - Backup file access
router.get("/backup", (req, res) => {
	try {
		const { backupId } = req.query;
		const fs = require("fs");
		
		// No validation on backup ID
		// Attack: /backup?backupId=../../../etc/passwd
		const backupPath = `./backups/backup_${backupId}.tar.gz`;
		const backup = fs.readFileSync(backupPath);
		
		res.setHeader('Content-Type', 'application/gzip');
		return res.send(backup);
	} catch (error) {
		Sentry.captureException(error);
		return res.status(404).json({ message: "Backup not found" });
	}
});

// VULNERABILITY A03: Path Traversal - CSV export
router.get("/export-csv", (req, res) => {
	try {
		const { reportName } = req.query;
		const fs = require("fs");
		const path = require("path");
		
		// Weak extension check can be bypassed
		// Attack: /export-csv?reportName=../../../etc/passwd.csv
		const csvPath = path.join('./exports', `${reportName}.csv`);
		const csvData = fs.readFileSync(csvPath, 'utf8');
		
		res.setHeader('Content-Type', 'text/csv');
		return res.send(csvData);
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Export failed" });
	}
});

// VULNERABILITY A03: Path Traversal - Directory listing
router.get("/list-directory", (req, res) => {
	try {
		const { dir } = req.query;
		const fs = require("fs");
		const path = require("path");
		
		// No validation - can list any directory
		// Attack: /list-directory?dir=../../../etc
		const dirPath = path.join('./data', dir);
		const files = fs.readdirSync(dirPath);
		
		return res.json({ success: true, files });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Could not list directory" });
	}
});

// VULNERABILITY A03: Path Traversal - Delete file
router.delete("/delete-file", (req, res) => {
	try {
		const { filepath } = req.body;
		const fs = require("fs");
		
		// No validation - can delete any file
		// Attack: filepath="../../../important-file.txt"
		fs.unlinkSync(filepath);
		
		return res.json({ success: true, message: "File deleted" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Could not delete file" });
	}
});

// VULNERABILITY A03: Path Traversal - Move/Rename file
router.post("/move-file", (req, res) => {
	try {
		const { source, destination } = req.body;
		const fs = require("fs");
		
		// No validation on source or destination
		// Attack: source="data.txt" destination="../../../etc/important"
		fs.renameSync(source, destination);
		
		return res.json({ success: true, message: "File moved" });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Could not move file" });
	}
});

// VULNERABILITY A03: Path Traversal - Include/Require file
router.post("/load-module", (req, res) => {
	try {
		const { modulePath } = req.body;
		
		// Dynamic require without validation
		// Attack: modulePath="../../../etc/passwd"
		const module = require(modulePath);
		
		return res.json({ success: true, module });
	} catch (error) {
		Sentry.captureException(error);
		return res.status(500).json({ message: "Could not load module" });
	}
});


export default router;
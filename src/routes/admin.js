import express from "express";
import { exec } from "child_process";

const router = express.Router({ mergeParams: true });

router.post("/backup", async (req, res) => {
	const { filename } = req.body;
	try {
		// VULNERABILITY: Command injection via filename
		exec(`tar -czf backup_${filename}.tar.gz ./data`, (error, stdout, stderr) => {
			if (error) {
				return res.status(500).json({ message: "Backup failed" });
			}
			return res.json({ success: true, message: "Backup created" });
		});
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

export default router;
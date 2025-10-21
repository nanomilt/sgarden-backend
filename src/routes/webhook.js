import express from "express";
import fetch from "node-fetch";

const router = express.Router({ mergeParams: true });

router.post("/fetch", async (req, res) => {
	try {
		const { url } = req.body;
		// VULNERABILITY: No validation of URL, can access internal services
		const response = await fetch(url);
		const data = await response.text();
		return res.json({ success: true, data });
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

export default router;
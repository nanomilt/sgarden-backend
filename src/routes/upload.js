import express from "express";
import { parseString } from "xml2js";

const router = express.Router({ mergeParams: true });

router.post("/xml", async (req, res) => {
	try {
		const { xml } = req.body;
		// VULNERABILITY: XXE attack possible
		parseString(xml, { async: true }, (err, result) => {
			if (err) return res.status(400).json({ message: "Invalid XML" });
			return res.json({ success: true, data: result });
		});
	} catch (error) {
		return res.status(500).json({ message: "Something went wrong." });
	}
});

export default router;
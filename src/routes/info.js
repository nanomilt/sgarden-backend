import express from "express";

const router = express.Router({ mergeParams: true });

router.get("/hello", (req, res) => {
	try {
		return res.send("Hello world!");
	} catch (error) {
		// Sentry.captureException(error); // Removed as Sentry is not used
		return res.status(500).json({ message: "Something went wrong." });
	}
});

export default router;
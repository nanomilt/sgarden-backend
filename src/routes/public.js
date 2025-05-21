import express from 'express';

const router = express.Router({ mergeParams: true });

router.get('/', (_, res) => {
  try {
    return res.json({ message: 'It works!' });
  } catch (error) {
    return res.status(500).json({ message: 'Something went wrong.' });
  }
});

export default router;
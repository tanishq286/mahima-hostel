const { handleUpload } = require('@vercel/blob/client');

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  const hasBlobToken = !!process.env.BLOB_READ_WRITE_TOKEN;
  const hasPassword = !!process.env.GALLERY_PASSWORD;
  if (!hasBlobToken) return res.status(500).json({ error: 'BLOB_READ_WRITE_TOKEN env var is missing.' });
  if (!hasPassword) return res.status(500).json({ error: 'GALLERY_PASSWORD env var is missing.' });

  try {
    const jsonResponse = await handleUpload({
      body: req.body,
      request: req,
      onBeforeGenerateToken: async (pathname, clientPayload) => {
        let payload = {};
        try { payload = JSON.parse(clientPayload || '{}'); } catch (_) {}
        if (!payload.password || payload.password !== process.env.GALLERY_PASSWORD) {
          throw new Error('Wrong gallery password.');
        }
        return {
          allowedContentTypes: ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4', 'video/webm'],
          maximumSizeInBytes: 500 * 1024 * 1024,
        };
      },
      onUploadCompleted: async () => { /* registration happens via explicit POST /api/gallery */ },
    });
    return res.status(200).json(jsonResponse);
  } catch (err) {
    console.error('[gallery-upload] ERROR', err);
    return res.status(400).json({ error: err.message || 'Unknown error' });
  }
};

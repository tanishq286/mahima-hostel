const { handleUpload } = require('@vercel/blob/client');
const { put, list } = require('@vercel/blob');

async function readGallery() {
  if (!process.env.BLOB_READ_WRITE_TOKEN) return { items: [] };
  const { blobs } = await list({ prefix: 'gallery.json', limit: 1 });
  if (!blobs.length) return { items: [] };
  const res = await fetch(blobs[0].url + '?v=' + Date.now());
  if (!res.ok) return { items: [] };
  return res.json();
}

async function writeGallery(data) {
  await put('gallery.json', JSON.stringify(data, null, 2) + '\n', {
    access: 'public',
    contentType: 'application/json',
    addRandomSuffix: false,
  });
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Method not allowed.' });
  }

  try {
    const jsonResponse = await handleUpload({
      body: req.body,
      request: req,
      onBeforeGenerateToken: async (pathname, clientPayload) => {
        let payload = {};
        try { payload = JSON.parse(clientPayload || '{}'); } catch (_) {}
        if (!payload.password || payload.password !== process.env.GALLERY_PASSWORD) {
          throw new Error('Wrong password.');
        }
        return {
          allowedContentTypes: ['image/jpeg', 'image/png', 'image/webp', 'image/gif', 'video/mp4', 'video/webm'],
          maximumSizeInBytes: 500 * 1024 * 1024,
          tokenPayload: JSON.stringify({
            category: payload.category || 'facilities',
            alt: payload.alt || pathname.split('/').pop(),
            type: (payload.fileType || '').startsWith('video') ? 'video' : 'image',
          }),
        };
      },
      onUploadCompleted: async ({ blob, tokenPayload }) => {
        const meta = JSON.parse(tokenPayload || '{}');
        const gallery = await readGallery();
        gallery.items.push({
          type: meta.type || 'image',
          category: meta.category || 'facilities',
          src: blob.url,
          blobUrl: blob.url,
          alt: meta.alt || blob.pathname.split('/').pop(),
        });
        await writeGallery(gallery);
      },
    });
    return res.status(200).json(jsonResponse);
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
};

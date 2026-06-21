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

  const hasBlobToken = !!process.env.BLOB_READ_WRITE_TOKEN;
  const hasPassword = !!process.env.GALLERY_PASSWORD;
  console.log('[gallery-upload] start', { hasBlobToken, hasPassword, bodyType: typeof req.body });

  if (!hasBlobToken) {
    return res.status(500).json({ error: 'BLOB_READ_WRITE_TOKEN env var is missing. Connect a Blob store to this project in Vercel.' });
  }
  if (!hasPassword) {
    return res.status(500).json({ error: 'GALLERY_PASSWORD env var is missing. Set it in Vercel project settings.' });
  }

  try {
    const jsonResponse = await handleUpload({
      body: req.body,
      request: req,
      onBeforeGenerateToken: async (pathname, clientPayload) => {
        let payload = {};
        try { payload = JSON.parse(clientPayload || '{}'); } catch (_) {}
        console.log('[gallery-upload] onBeforeGenerateToken', { pathname, hasPassword: !!payload.password });
        if (!payload.password || payload.password !== process.env.GALLERY_PASSWORD) {
          throw new Error('Wrong gallery password.');
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
        console.log('[gallery-upload] onUploadCompleted', { url: blob.url });
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
    console.error('[gallery-upload] ERROR', err);
    return res.status(400).json({ error: err.message || 'Unknown error', stack: err.stack });
  }
};

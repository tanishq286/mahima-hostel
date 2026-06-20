const { put, del, list } = require('@vercel/blob');

module.exports.config = {
  api: {
    bodyParser: {
      sizeLimit: '4mb',
    },
  },
};

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
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-gallery-password');

  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method === 'GET') {
    try {
      return res.status(200).json(await readGallery());
    } catch {
      return res.status(200).json({ items: [] });
    }
  }

  const pwd = req.headers['x-gallery-password'];
  if (!pwd || pwd !== process.env.GALLERY_PASSWORD) {
    return res.status(401).json({ error: 'Wrong password.' });
  }

  if (req.method === 'POST') {
    const { fileContent, fileName, fileType, category, alt } = req.body;
    if (!fileContent || !fileName) {
      return res.status(400).json({ error: 'fileContent and fileName are required.' });
    }

    const buf = Buffer.from(fileContent, 'base64');
    const safe = Date.now() + '-' + fileName.toLowerCase().replace(/[^a-z0-9.]+/g, '-');
    const blob = await put('gallery/' + safe, buf, {
      access: 'public',
      contentType: fileType || 'application/octet-stream',
      addRandomSuffix: false,
    });

    const gallery = await readGallery();
    gallery.items.push({
      type: (fileType || '').startsWith('video') ? 'video' : 'image',
      category: category || 'facilities',
      src: blob.url,
      blobUrl: blob.url,
      alt: alt || safe,
    });
    await writeGallery(gallery);
    return res.status(200).json({ ok: true, gallery });
  }

  if (req.method === 'DELETE') {
    const { index } = req.body;
    const gallery = await readGallery();
    if (typeof index !== 'number' || index < 0 || index >= gallery.items.length) {
      return res.status(400).json({ error: 'Invalid index.' });
    }
    const [item] = gallery.items.splice(index, 1);
    await writeGallery(gallery);
    if (item.blobUrl) { try { await del(item.blobUrl); } catch (_) {} }
    return res.status(200).json({ ok: true, gallery });
  }

  return res.status(405).json({ error: 'Method not allowed.' });
};

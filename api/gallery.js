const { put, del, list } = require('@vercel/blob');

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
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-gallery-password');

  if (req.method === 'OPTIONS') return res.status(200).end();

  if (req.method === 'GET') {
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
    try {
      return res.status(200).json(await readGallery());
    } catch {
      return res.status(200).json({ items: [] });
    }
  }

  const pwd = req.headers['x-gallery-password'];
  if (!pwd || pwd !== process.env.GALLERY_PASSWORD) {
    return res.status(401).json({ error: 'Wrong gallery password.' });
  }

  if (req.method === 'POST') {
    const { blobUrl, type, category, alt } = req.body || {};
    if (!blobUrl) return res.status(400).json({ error: 'blobUrl is required.' });
    const gallery = await readGallery();
    gallery.items.push({
      type: type || 'image',
      category: category || 'facilities',
      src: blobUrl,
      blobUrl,
      alt: alt || blobUrl.split('/').pop(),
    });
    await writeGallery(gallery);
    return res.status(200).json({ ok: true, gallery });
  }

  if (req.method === 'PUT') {
    const { items } = req.body || {};
    if (!Array.isArray(items)) return res.status(400).json({ error: 'items array required.' });
    await writeGallery({ items });
    return res.status(200).json({ ok: true, gallery: { items } });
  }

  if (req.method === 'DELETE') {
    const { index } = req.body || {};
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

require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const fs = require('fs').promises;
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');

const SECRET_KEY = process.env.SECRET_KEY;
const PASSWORD = process.env.PASSWORD;
const MONGO_URI = process.env.MONGO_URI;

// Middleware to parse URL-encoded bodies (for bulk delete form)
app.use(express.json());
app.use(express.urlencoded({ extended: true, limit: '500mb', parameterLimit: 10000 }));
app.use(express.json({ limit: '500mb' }));

// Ensure uploads directory exists
fs.mkdir(UPLOAD_DIR, { recursive: true }).catch(err => console.error(err));

// MongoDB Connection
mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// File Schema & Model
const fileSchema = new mongoose.Schema({
  filename: String,
  originalname: String,
  iv: String,
  uploadDate: { type: Date, default: Date.now }
});
const File = mongoose.model('File', fileSchema);

// Password middleware: checks password in header, query, or body.
const passwordMiddleware = (req, res, next) => {
  const password = req.headers['x-password'] || req.query.password || req.body?.password;
  if (password !== PASSWORD) {
    return res.status(401).json({ message: 'Unauthorized: Invalid password' });
  }
  next();
};

// Helper: derive 32-byte key from SECRET_KEY
const getKey = () => crypto.createHash('sha256').update(SECRET_KEY).digest();

// Encryption functions (AES-256-CBC)
const encryptBuffer = (buffer) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return { iv: iv.toString('hex'), encrypted };
};

const decryptBuffer = (buffer, iv) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', getKey(), Buffer.from(iv, 'hex'));
  const decrypted = Buffer.concat([decipher.update(buffer), decipher.final()]);
  return decrypted;
};

app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(__dirname, 'icon.ico'));
});

// Download endpoint – supports inline display for thumbnails.
app.get('/download/:id([0-9a-fA-F]{24})', passwordMiddleware, async (req, res) => {
  try {
    const fileDoc = await File.findById(req.params.id);
    if (!fileDoc) return res.status(404).json({ message: 'File not found' });
    const filePath = path.join(UPLOAD_DIR, fileDoc.filename);
    const encryptedData = await fs.readFile(filePath);
    const decryptedData = decryptBuffer(encryptedData, fileDoc.iv);
    const ext = path.extname(fileDoc.originalname).toLowerCase();
    let contentType = 'application/octet-stream';
    if (['.jpg', '.jpeg'].includes(ext)) contentType = 'image/jpeg';
    else if (ext === '.png') contentType = 'image/png';
    else if (ext === '.gif') contentType = 'image/gif';
    res.setHeader('Content-Type', contentType);
    const disposition = req.query.inline === 'true'
      ? `inline; filename="${fileDoc.originalname}"`
      : `attachment; filename="${fileDoc.originalname}"`;
    res.setHeader('Content-Disposition', disposition);
    res.send(decryptedData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Download failed', error: err.message });
  }
});

// Single deletion endpoint
app.get('/delete/:id', passwordMiddleware, async (req, res) => {
  try {
    const fileDoc = await File.findById(req.params.id);
    if (!fileDoc) return res.status(404).json({ message: 'File not found' });
    await fs.unlink(path.join(UPLOAD_DIR, fileDoc.filename));
    await File.deleteOne({ _id: req.params.id });
    res.redirect(`/?password=${req.query.password}`);
  } catch (err) {
    res.status(500).json({ message: 'Delete failed', error: err.message });
  }
});

// Bulk deletion endpoint (POST)
app.post('/delete', passwordMiddleware, async (req, res) => {
  try {
    let ids = req.body.ids;
    if (!ids) return res.redirect(`/?password=${req.query.password}`);
    if (!Array.isArray(ids)) ids = [ids];
    for (let id of ids) {
      const fileDoc = await File.findById(id);
      if (fileDoc) {
        await fs.unlink(path.join(UPLOAD_DIR, fileDoc.filename));
        await File.deleteOne({ _id: id });
      }
    }
    console.log(`Deleted files: ${ids.join(', ')}`);
    res.redirect(`/?password=${req.query.password}`);
  } catch (err) {
    res.status(500).json({ message: 'Bulk delete failed', error: err.message });
  }
});

// Minimal ZIP generator (store method, no compression)
function makeCRCTable() {
  let c, crcTable = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
    }
    crcTable[n] = c;
  }
  return crcTable;
}
const crcTable = makeCRCTable();
function crc32(buf) {
  let crc = 0 ^ (-1);
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ crcTable[(crc ^ buf[i]) & 0xFF];
  }
  return (crc ^ (-1)) >>> 0;
}

// Bulk download endpoint: accepts comma-separated file IDs via "ids"
app.post('/download/bulk', passwordMiddleware, async (req, res) => {
  try {
    // Expect req.body.ids to be either an array or a comma-separated string.
    let ids = req.body.ids;
    if (!ids) {
      return res.status(400).json({ message: 'No file IDs provided' });
    }
    if (!Array.isArray(ids)) {
      // If a comma-separated string was sent, convert it to an array.
      ids = typeof ids === 'string' ? ids.split(',') : [ids];
    }

    // Set headers for ZIP download.
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="files.zip"');

    // Retrieve file records from the database.
    const files = await File.find({ _id: { $in: ids } });
    
    let offset = 0;
    const centralDirectoryRecords = [];
    
    // Process files sequentially.
    for (const fileDoc of files) {
      const filePath = path.join(UPLOAD_DIR, fileDoc.filename);
      // Read encrypted file and decrypt it.
      const encryptedData = await fs.readFile(filePath);
      const decryptedData = decryptBuffer(encryptedData, fileDoc.iv);
      
      // Compute CRC and size.
      const crc = crc32(decryptedData);
      const size = decryptedData.length;
      
      // Create local file header.
      const localHeader = createLocalHeader(fileDoc.originalname, crc, size);
      const headerOffset = offset; // Record starting offset.
      res.write(localHeader);
      offset += localHeader.length;
      
      // Write file data.
      res.write(decryptedData);
      offset += decryptedData.length;
      
      // Create central directory record for this file.
      const centralRecord = createCentralDirectoryRecord(fileDoc.originalname, crc, size, headerOffset);
      centralDirectoryRecords.push(centralRecord);
    }
    
    // Build and write the central directory.
    const centralDirectoryBuffer = Buffer.concat(centralDirectoryRecords);
    res.write(centralDirectoryBuffer);
    const centralDirectorySize = centralDirectoryBuffer.length;
    const centralDirectoryOffset = offset;
    offset += centralDirectorySize;
    
    // Write End Of Central Directory Record.
    const eocdr = createEOCDRecord(centralDirectoryRecords.length, centralDirectorySize, centralDirectoryOffset);
    res.write(eocdr);
    res.end();
    
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Bulk download failed', error: err.message });
  }
});

//
// Helper functions to build ZIP structures (store method, no compression)
//

// Local File Header Creator.
function createLocalHeader(filename, crc, size) {
  const filenameBuf = Buffer.from(filename, 'utf8');
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0);    // Local file header signature.
  header.writeUInt16LE(20, 4);              // Version needed to extract.
  header.writeUInt16LE(0, 6);               // General purpose bit flag.
  header.writeUInt16LE(0, 8);               // Compression method (0 = store).
  header.writeUInt16LE(0, 10);              // Last mod file time.
  header.writeUInt16LE(0, 12);              // Last mod file date.
  header.writeUInt32LE(crc, 14);            // CRC-32.
  header.writeUInt32LE(size, 18);           // Compressed size.
  header.writeUInt32LE(size, 22);           // Uncompressed size.
  header.writeUInt16LE(filenameBuf.length, 26); // File name length.
  header.writeUInt16LE(0, 28);              // Extra field length.
  return Buffer.concat([header, filenameBuf]);
}

// Central Directory Record Creator.
function createCentralDirectoryRecord(filename, crc, size, offset) {
  const filenameBuf = Buffer.from(filename, 'utf8');
  const record = Buffer.alloc(46);
  record.writeUInt32LE(0x02014b50, 0);     // Central file header signature.
  record.writeUInt16LE(20, 4);              // Version made by.
  record.writeUInt16LE(20, 6);              // Version needed to extract.
  record.writeUInt16LE(0, 8);               // General purpose bit flag.
  record.writeUInt16LE(0, 10);              // Compression method.
  record.writeUInt16LE(0, 12);              // Last mod file time.
  record.writeUInt16LE(0, 14);              // Last mod file date.
  record.writeUInt32LE(crc, 16);            // CRC-32.
  record.writeUInt32LE(size, 20);           // Compressed size.
  record.writeUInt32LE(size, 24);           // Uncompressed size.
  record.writeUInt16LE(filenameBuf.length, 28); // File name length.
  record.writeUInt16LE(0, 30);              // Extra field length.
  record.writeUInt16LE(0, 32);              // File comment length.
  record.writeUInt16LE(0, 34);              // Disk number start.
  record.writeUInt16LE(0, 36);              // Internal file attributes.
  record.writeUInt32LE(0, 38);              // External file attributes.
  record.writeUInt32LE(offset, 42);         // Relative offset of local header.
  return Buffer.concat([record, filenameBuf]);
}

// End Of Central Directory Record Creator.
function createEOCDRecord(totalEntries, centralDirectorySize, centralDirectoryOffset) {
  const eocdr = Buffer.alloc(22);
  eocdr.writeUInt32LE(0x06054b50, 0);       // EOCD signature.
  eocdr.writeUInt16LE(0, 4);                // Number of this disk.
  eocdr.writeUInt16LE(0, 6);                // Disk where central directory starts.
  eocdr.writeUInt16LE(totalEntries, 8);     // Number of central directory records on this disk.
  eocdr.writeUInt16LE(totalEntries, 10);    // Total number of central directory records.
  eocdr.writeUInt32LE(centralDirectorySize, 12); // Size of central directory (bytes).
  eocdr.writeUInt32LE(centralDirectoryOffset, 16); // Offset of start of central directory.
  eocdr.writeUInt16LE(0, 20);               // ZIP file comment length.
  return eocdr;
}
/* 
  Custom multipart parser.
  This function splits the raw buffer using the boundary string.
  It returns an array of parts, each with a "headers" string and a "data" Buffer.
*/
function parseMultipart(buffer, boundary) {
  const parts = [];
  const boundaryBuffer = Buffer.from(`--${boundary}`, 'utf-8');
  let start = buffer.indexOf(boundaryBuffer);
  if (start === -1) return parts;
  start += boundaryBuffer.length;
  while (true) {
    let end = buffer.indexOf(boundaryBuffer, start);
    if (end === -1) break;
    let partBuffer = buffer.slice(start, end);
    // Trim leading and trailing CRLF
    if (partBuffer.slice(0, 2).toString() === '\r\n') {
      partBuffer = partBuffer.slice(2);
    }
    if (partBuffer.slice(-2).toString() === '\r\n') {
      partBuffer = partBuffer.slice(0, partBuffer.length - 2);
    }
    // Split headers and body by the first occurrence of double CRLF.
    const delimiter = Buffer.from('\r\n\r\n');
    const headerEnd = partBuffer.indexOf(delimiter);
    if (headerEnd !== -1) {
      const headers = partBuffer.slice(0, headerEnd).toString('utf-8');
      const data = partBuffer.slice(headerEnd + delimiter.length);
      parts.push({ headers, data });
    }
    start = end + boundaryBuffer.length;
    // Check if this is the final boundary marker.
    if (buffer.slice(start, start + 2).toString() === '--') break;
  }
  return parts;
}

app.post('/upload', passwordMiddleware, (req, res) => {
  console.log(`User logged in. Upload started at ${new Date().toISOString()}`);
  const contentType = req.headers['content-type'];
  const boundaryMatch = contentType && contentType.match(/boundary=(.+)$/);
  if (!boundaryMatch) {
    return res.status(400).json({ message: 'Invalid form-data: No boundary found' });
  }
  const boundary = boundaryMatch[1];
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', async () => {
    try {
      const buffer = Buffer.concat(chunks);
      const parts = parseMultipart(buffer, boundary);
      const fileUploads = [];
      for (let part of parts) {
        if (part.headers.includes('Content-Disposition') && part.headers.includes('filename="')) {
          const filenameMatch = part.headers.match(/filename="([^"]+)"/);
          if (!filenameMatch) continue;
          const originalname = filenameMatch[1];
          // Encrypt the file data using your encryptBuffer function.
          const { iv, encrypted } = encryptBuffer(part.data);
          const uniqueFilename = `${Date.now()}-${originalname}`;
          const filePath = path.join(UPLOAD_DIR, uniqueFilename);
          await fs.writeFile(filePath, encrypted);
          fileUploads.push({ originalname, filename: uniqueFilename, iv });
          console.log(`Uploaded file: ${originalname} as ${uniqueFilename}`);
        }
      }
      if (fileUploads.length > 0) {
        await File.insertMany(fileUploads);
        console.log(`Successfully saved ${fileUploads.length} file(s) to database.`);
      }
      // Build a simple HTML response that includes login status and an advertisement snippet.
      const responseHTML = `
      <!DOCTYPE html>
      <html>
      <head>
        <title>Upload Status</title>
        <style>
          body { font-family: Arial, sans-serif; background-color: #f5f5f5; padding: 20px; }
          .container { background: white; padding: 20px; border-radius: 8px; max-width: 600px; margin: auto; }
          .ad { background: #e2e2e2; padding: 10px; margin-top: 20px; border-radius: 4px; text-align: center; }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>Upload Complete</h1>
          <p>You are logged in.</p>
          <p>Uploaded ${fileUploads.length} file(s) successfully.</p>
          <p><a href="/?password=${req.query.password}">Return to Gallery</a></p>
          <div class="ad">
            <p>Advertisement: Upgrade to our premium plan for faster uploads and exclusive features!</p>
          </div>
        </div>
      </body>
      </html>`;
      res.send(responseHTML);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Upload failed', error: err.message });
    }
  });
});

// Helper function to format file sizes
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024,
        dm = decimals < 0 ? 0 : decimals,
        sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'],
        i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// Gallery view endpoint
app.get('/', passwordMiddleware, async (req, res) => {
  try {
    const password = req.query.password;
    const sortOption = req.query.sort || 'desc';
    let files 
    if (sortOption === 'asc') {
      files = await File.find({}, 'originalname _id filename uploadDate').sort({ uploadDate: 1 });
    } else if (sortOption === 'desc') {
      files = await File.find({}, 'originalname _id filename uploadDate').sort({ uploadDate: -1 });
    } else if (sortOption === 'random') {
      files = await File.find({}, 'originalname _id filename uploadDate');
      files.sort(() => Math.random() - 0.5);
    } else if (sortOption === 'gif') {
        files = await File.find({}, 'originalname _id filename uploadDate');
        files.sort((a, b) => {
          const isAGif = a.filename.endsWith('.gif') ? -1 : 1;
          const isBGif = b.filename.endsWith('.gif') ? -1 : 1;
          return isAGif - isBGif || b.uploadDate - a.uploadDate;
        });
    } else if (sortOption === 'video') {
        files = await File.find({}, 'originalname _id filename uploadDate');
        files.sort((a, b) => {
          const isAVideo = /\.(mp4|mov|avi|mkv|webm)$/i.test(a.filename) ? -1 : 1;
          const isBVideo = /\.(mp4|mov|avi|mkv|webm)$/i.test(b.filename) ? -1 : 1;
          return isAVideo - isBVideo || b.uploadDate - a.uploadDate;
        });
    } else {
      files = await File.find({}, 'originalname _id filename uploadDate').sort({ uploadDate: -1 });
    }
    const galleryFiles = files.map(file => {
      const ext = path.extname(file.originalname).toLowerCase();
      const type = ['.mp4', '.webm', '.ogg', '.mov', '.avi', '.flv'].includes(ext) ? 'video' : 'image';
      return {
        id: file._id,
        originalname: file.originalname,
        type,
        url: `/download/${file._id}?password=${password}&inline=true`,
        filename: file.filename
      };
        })
    const galleryItems = await Promise.all(galleryFiles.map(async (file, index) => {
      const filePath = path.join(UPLOAD_DIR, file.filename);
      let sizeStr = "N/A";
      try {
        const stats = await fs.stat(filePath);
        sizeStr = formatBytes(stats.size);
      } catch (e) { /* ignore error */ }
      const mediaTag = file.type === 'image'
        ? `<img loading="lazy" src="${file.url}" alt="${file.originalname}">`
        : `<video loading="lazy" src="${file.url}" muted playsinline preload="auto"></video>`;
      return `
      <div class="gallery-item" data-index="${index}" data-id="${file.id}" onclick="handleGalleryItemClick(event, ${index}, '${file.id}')">
        <div class="image-box">${mediaTag}</div>
        <div class="info-box">
          <div class="file-details">
            <div class="file-name">${file.originalname}</div>
            <div class="file-size">${sizeStr}</div>
          </div>
          <div class="actions">
            <a href="/download/${file.id}?password=${password}">Download</a>
            <a href="/delete/${file.id}?password=${password}" onclick="return confirm('Delete ${file.originalname}?')">Delete</a>
          </div>
        </div>
        <!-- Hidden checkbox for bulk actions -->
        <input type="checkbox" name="ids" value="${file.id}" id="cb-${file.id}" style="display:none;">
      </div>`;
    }));
    const header = `
      <div style="text-align:center; margin-bottom:20px; color:#fff; font-size:1.2em;">
        Total files: ${galleryFiles.length}
      </div>
    `;

    const sortOptionsHTML = `
      <div class="sort-options" style="text-align:center; margin-bottom:20px;">
        <label for="sortSelect" style="margin-right: 10px;">Sort by:</label>
        <select id="sortSelect">
          <option value="desc" ${sortOption==='desc'?'selected':''}>Last Uploaded</option>
          <option value="asc" ${sortOption==='asc'?'selected':''}>First Uploaded</option>
          <option value="random" ${sortOption==='random'?'selected':''}>Random</option>
          <option value="gif" ${sortOption==='gif'?'selected':''}>gif</option>
          <option value="video" ${sortOption==='video'?'selected':''}>video</option>
        </select>
      </div>
    `;
    const html = `
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Image & Video Uploader & Downloader</title>
        <link rel="icon" href="favicon.ico" type="image/x-icon">
        <meta name="description" content="Upload and download your images and videos easily with our platform.">
        <meta name="keywords" content="image uploader, video uploader, file downloader">
        <meta name="author" content="Your Name">
        <style>
          body { background: #202123; color: #E4E6EB; font-family: Arial, sans-serif; margin: 0; padding: 20px; }
          .container { max-width: 1200px; margin: auto; background: #2D2F31; padding: 20px; border-radius: 8px; box-shadow: 0 2px 8px rgba(0,0,0,0.5); }
          h1, h2 { color: #ffffff; text-align: center; }
          form.upload-form { margin-bottom: 20px; text-align: center; }
          input[type="file"] { display: block; margin: auto; margin-bottom: 10px; background: #3A3B3C; color: #ffffff; border: none; padding: 8px; border-radius: 4px; width: 90%; max-width: 400px; }
          button { background: #4A90E2; color: #ffffff; border: none; padding: 10px 20px; border-radius: 4px; cursor: pointer; font-size: 1em; margin: 5px; }
          button:hover { background: #357ABD; }
          .grid-options { text-align: center; margin-bottom: 20px; }
          .grid-options select { background: #3A3B3C; color: #ffffff; border: none; padding: 5px; border-radius: 4px; font-size: 1em; }
          .gallery { display: grid; gap: 10px; margin-top: 20px; grid-template-columns: repeat(3, 1fr); }
          .gallery-item { background: #3A3B3C; border-radius: 4px; position: relative; cursor: pointer; overflow: hidden; height: 250px; display: flex; flex-direction: column; }
          .gallery-item .image-box { flex: 8; overflow: hidden; }
          .gallery-item .image-box img, .gallery-item .image-box video { width: 100%; height: 100%; object-fit: cover; display: block; }
          .gallery-item .info-box { flex: 2; display: flex; align-items: center; justify-content: space-between; padding: 0 5px; background: rgba(0,0,0,0.7); }
          .gallery-item .file-details { color: #fff; font-size: 0.8em; overflow: hidden; white-space: nowrap; text-overflow: ellipsis; }
          .gallery-item .actions a { color: #4A90E2; text-decoration: none; margin-left: 5px; font-size: 0.8em; }
          .gallery-item.selected::after { content: "\\2713"; position: absolute; top: 5px; right: 5px; font-size: 24px; color: #4A90E2; background: rgba(0, 0, 0, 0.6); padding: 4px; border-radius: 50%; z-index: 4; }
          .controls { text-align: center; margin-top: 20px; }
          #selectionControls { display: none; }
          .modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: hidden; background-color: rgba(0,0,0,0.9); }
          .modal-content { position: relative; margin: auto; width: 90vw; height: 90vh; text-align: center; }
          .modal-media-container { width: 100%; height: calc(100% - 60px); display: flex; align-items: center; justify-content: center; }
          .modal-media-container img, .modal-media-container video { max-width: 100%; max-height: 100%; object-fit: contain; }
          .close { position: absolute; top: 10px; right: 25px; color: #fff; font-size: 35px; font-weight: bold; cursor: pointer; }
          .modal-actions { margin-top: 10px; }
          .modal-actions a { color: #4A90E2; text-decoration: none; margin: 0 10px; font-size: 1em; }
          .prev, .next { cursor: pointer; position: absolute; top: 50%; padding: 16px; color: #fff; font-weight: bold; font-size: 20px; transition: 0.3s; user-select: none; background: rgba(0,0,0,0.5); border: none; }
          .prev:hover, .next:hover { background: rgba(0,0,0,0.8); }
          .prev { left: 0; border-radius: 0 3px 3px 0; }
          .next { right: 0; border-radius: 3px 0 0 3px; }
          @media screen and (max-width: 600px) { .gallery { grid-template-columns: repeat(2, 1fr); } }
        </style>
        <script>
          let currentIndex = 0, selectMode = false;
          const galleryFiles = ${JSON.stringify(galleryFiles)};
          const password = "${password}";
          function toggleSelectMode() {
            selectMode = !selectMode;
            const btn = document.getElementById('toggleSelectMode');
            btn.innerText = selectMode ? "Exit Select Mode" : "Enter Select Mode";
            document.getElementById('selectionControls').style.display = selectMode ? "block" : "none";
            if (!selectMode) {
              document.querySelectorAll('.gallery-item.selected').forEach(item => {
                item.classList.remove('selected');
                const id = item.getAttribute('data-id');
                document.getElementById('cb-' + id).checked = false;
              });
            }
          }
          function handleGalleryItemClick(event, index, fileId) {
            event.stopPropagation();
            if (selectMode) toggleSelection(fileId);
            else openModal(event, index);
          }
          function toggleSelection(fileId) {
            const item = document.querySelector('.gallery-item[data-id="' + fileId + '"]');
            const cb = document.getElementById('cb-' + fileId);
            if (cb.checked) { cb.checked = false; item.classList.remove('selected'); }
            else { cb.checked = true; item.classList.add('selected'); }
          }
          function selectAllItems() {
            document.querySelectorAll('.gallery-item').forEach(item => {
              const id = item.getAttribute('data-id');
              item.classList.add('selected');
              document.getElementById('cb-' + id).checked = true;
            });
          }
          function deselectAllItems() {
            document.querySelectorAll('.gallery-item').forEach(item => {
              const id = item.getAttribute('data-id');
              item.classList.remove('selected');
              document.getElementById('cb-' + id).checked = false;
            });
          }
          function openModal(event, index) {
            if (event.target.closest('.info-box')) return;
            currentIndex = index;
            updateModal();
            updateButtons();
            document.getElementById('modal').style.display = "block";
          }
          function closeModal(event) {
            if (event.target.closest('.modal-media-container img, .modal-media-container video')) return;
            document.getElementById('modal').style.display = "none";
            const video = document.getElementById('modalVideo');
            if (video) { video.pause(); video.currentTime = 0; }
            currentIndex = -1;
            updateButtons();
          }
          function updateModal() {
            const file = galleryFiles[currentIndex];
            const container = document.getElementById('modalMediaContainer');
            if(file.type === 'image')
              container.innerHTML = '<img src="' + file.url + '" alt="' + file.originalname + '">';
            else
              container.innerHTML = '<video src="' + file.url + '" controls autoplay playsinline id="modalVideo">Your browser does not support the video tag.</video>';
            document.getElementById('modalDownload').href = "/download/" + file.id + "?password=" + password;
            document.getElementById('modalDelete').href = "/delete/" + file.id + "?password=" + password;
            document.getElementById('modalCounter').innerText = (currentIndex + 1) + " / " + galleryFiles.length;
          }
          function nextModal() { if(currentIndex < galleryFiles.length - 1) { currentIndex++; updateModal(); updateButtons(); } }
          function prevModal() { if(currentIndex > 0) { currentIndex--; updateModal(); updateButtons(); } }
          function updateButtons() {
            document.getElementById('nextButton').style.display = currentIndex < galleryFiles.length - 1 ? 'inline-block' : 'none';
            document.getElementById('prevButton').style.display = currentIndex > 0 ? 'inline-block' : 'none';
          }
          function getCheckedIds() {
            const ids = [];
            document.querySelectorAll('.gallery-item input[type="checkbox"]').forEach(cb => { if(cb.checked) ids.push(cb.value); });
            return ids;
          }
           function bulkDownload() {
              const ids = getCheckedIds();
              if (ids.length === 0) {
                alert("No files selected for bulk download.");
                return;
              }
              // Create a form dynamically.
              const form = document.createElement("form");
              form.method = "POST";
              form.action = "/download/bulk";
              // Add the password field.
              const passwordInput = document.createElement("input");
              passwordInput.type = "hidden";
              passwordInput.name = "password";
              passwordInput.value = password;
              form.appendChild(passwordInput);
              // Add the selected file IDs. (For multiple values, use the same name)
              ids.forEach(function(id) {
                const input = document.createElement("input");
                input.type = "hidden";
                input.name = "ids";
                input.value = id;
                form.appendChild(input);
              });
              document.body.appendChild(form);
              form.submit();
            }
          function bulkDelete() {
            const ids = getCheckedIds();
            if(ids.length === 0) { alert("No files selected for bulk delete."); return; }
            if(!confirm("Delete selected files?")) return;
            const form = document.createElement("form");
            form.method = "POST";
            form.action = "/delete?password=" + password;
            ids.forEach(function(id) {
              const input = document.createElement("input");
              input.type = "hidden";
              input.name = "ids";
              input.value = id;
              form.appendChild(input);
            });
            document.body.appendChild(form);
            form.submit();
          }
          document.addEventListener("DOMContentLoaded", function() {
            document.getElementById('columnsSelect').addEventListener('change', function() {
              document.querySelector('.gallery').style.gridTemplateColumns = 'repeat(' + this.value + ', 1fr)';
            });
              // Sorting dropdown change event.
            document.getElementById('sortSelect').addEventListener('change', function() {
              window.location.href = "/?password=" + password + "&sort=" + this.value;
            });
          });
         

          document.getElementById('modalMediaContainer').addEventListener('click', function(event) { event.stopPropagation(); });
        </script>
      </head>
      <body>
        <div class="container">
          <h1>Image & Video Uploader & Downloader</h1>
           ${header}
           ${sortOptionsHTML}
          <form class="upload-form" action="/upload?password=${password}" method="POST" enctype="multipart/form-data">
            <input type="file" name="files" accept="image/*,video/*" multiple required>
            <button type="submit">Upload</button>
          </form>
          <div class="controls">
            <button id="toggleSelectMode" type="button" onclick="toggleSelectMode()">Enter Select Mode</button>
            <div id="selectionControls">
              <button type="button" onclick="selectAllItems()">Select All</button>
              <button type="button" onclick="deselectAllItems()">Deselect All</button>
              <button type="button" onclick="bulkDownload()">Bulk Download</button>
              <button type="button" onclick="bulkDelete()">Bulk Delete</button>
            </div>
          </div>
          <div class="grid-options">
            <label for="columnsSelect">Files per row:</label>
            <select id="columnsSelect">
              <option value="3">3</option>
              <option value="6">6</option>
              <option value="9">9</option>
            </select>
          </div>
          <div class="gallery">
            ${galleryItems.join('')}
          </div>
        </div>
        <!-- Modal for full-screen view -->
        <div id="modal" class="modal">
          <div class="modal-content">
            <span class="close" onclick="closeModal(event)">&times;</span>
            <button class="prev" onclick="prevModal()" id="prevButton" style="display: none;">&#10094;</button>
            <div id="modalMediaContainer" onclick="closeModal(event)" class="modal-media-container"></div>
            <button class="next" onclick="nextModal()" id="nextButton" style="display: none;">&#10095;</button>
            <div class="modal-actions">
              <a id="modalDownload" href="">Download</a>
              <a id="modalDelete" href="" onclick="return confirm('Delete this file?')">Delete</a>
            </div>
            <div class="modal-counter" id="modalCounter"></div>
          </div>
        </div>
      </body>
    </html>`;
    res.send(html);
  } catch (err) {
    res.status(500).json({ message: 'Error rendering gallery', error: err.message });
  }
});

app.listen(PORT, "0.0.0.0", () => console.log(`Server running on port ${PORT}`));

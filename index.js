require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Secret key for encryption (store securely in production)
const SECRET_KEY = process.env.SECRET_KEY;
const PASSWORD = process.env.PASSWORD;
const MONGO_URI = process.env.MONGO_URI;


// Middleware to parse URL-encoded bodies (for bulk delete form)
app.use(express.urlencoded({ extended: true }));

// Ensure uploads directory exists
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR);
}

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

// Password middleware: reads password from query, headers, or body.
const passwordMiddleware = (req, res, next) => {
  const password = req.headers['x-password'] || req.query.password || req.body?.password;
  if (password !== PASSWORD) {
    return res.status(401).json({ message: 'Unauthorized: Invalid password' });
  }
  next();
};

// Helper to get a 32-byte key from SECRET_KEY
const getKey = () => crypto.createHash('sha256').update(SECRET_KEY).digest();

// Encrypt and Decrypt functions (AES-256-CBC)
const encryptFile = (buffer) => {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', getKey(), iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return { iv: iv.toString('hex'), encrypted };
};

const decryptFile = (buffer, iv) => {
  const decipher = crypto.createDecipheriv('aes-256-cbc', getKey(), Buffer.from(iv, 'hex'));
  const decrypted = Buffer.concat([decipher.update(buffer), decipher.final()]);
  return decrypted;
};


app.get('/favicon.ico', (req, res) => {
  res.sendFile(path.join(__dirname, 'icon.ico'));
});


// Download endpoint – if ?inline=true, set Content-Disposition inline (for thumbnails)
app.get('/download/:id([0-9a-fA-F]{24})', passwordMiddleware, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ message: 'File not found' });
    const filePath = path.join(UPLOAD_DIR, file.filename);
    const encryptedData = fs.readFileSync(filePath);
    const decryptedData = decryptFile(encryptedData, file.iv);
    const ext = path.extname(file.originalname).toLowerCase();
    let contentType = 'application/octet-stream';
    if (ext === '.jpg' || ext === '.jpeg') contentType = 'image/jpeg';
    else if (ext === '.png') contentType = 'image/png';
    else if (ext === '.gif') contentType = 'image/gif';
    res.setHeader('Content-Type', contentType);
    const disposition = req.query.inline
      ? `inline; filename="${file.originalname}"`
      : `attachment; filename="${file.originalname}"`;
    res.setHeader('Content-Disposition', disposition);
    res.send(decryptedData);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Download failed', error: err.message });
  }
});
// Individual deletion endpoint
app.get('/delete/:id', passwordMiddleware, async (req, res) => {
  try {
    const file = await File.findById(req.params.id);
    if (!file) return res.status(404).json({ message: 'File not found' });
    fs.unlinkSync(path.join(UPLOAD_DIR, file.filename));
    await File.deleteOne({ _id: req.params.id });
    res.redirect(`/?password=${req.query.password}`);
  } catch (err) {
    res.status(500).json({ message: 'Delete failed', error: err.message });
  }
});

// Bulk deletion endpoint (POST)
app.post('/delete', passwordMiddleware, async (req, res) => {
  try {
    const ids = req.body.ids;
    if (!ids) return res.redirect(`/?password=${req.query.password}`);
    const idArray = Array.isArray(ids) ? ids : [ids];
    for (let id of idArray) {
      const file = await File.findById(id);
      if (file) {
        fs.unlinkSync(path.join(UPLOAD_DIR, file.filename));
        await File.deleteOne({ _id: id });
      }
    }
    console.log(`Deleted files: ${idArray.join(', ')}`);
    console.log(`Redirecting to /?password=${req.query.password}`);
    res.redirect(`/?password=${req.query.password}`);
  } catch (err) {
    res.status(500).json({ message: 'Bulk delete failed', error: err.message });
  }
});

// Minimal ZIP generator (store method, no compression)
function makeCRCTable() {
  let c;
  const crcTable = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) {
      c = ((c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1));
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
function createZip(files) {
  let fileRecords = [];
  let offset = 0;
  const localFileBuffers = [];
  files.forEach(file => {
    const fileNameBuffer = Buffer.from(file.name);
    const fileData = file.data;
    const crc = crc32(fileData);
    const localHeader = Buffer.alloc(30);
    localHeader.writeUInt32LE(0x04034b50, 0);
    localHeader.writeUInt16LE(20, 4);
    localHeader.writeUInt16LE(0, 6);
    localHeader.writeUInt16LE(0, 8);
    localHeader.writeUInt16LE(0, 10);
    localHeader.writeUInt16LE(0, 12);
    localHeader.writeUInt32LE(crc, 14);
    localHeader.writeUInt32LE(fileData.length, 18);
    localHeader.writeUInt32LE(fileData.length, 22);
    localHeader.writeUInt16LE(fileNameBuffer.length, 26);
    localHeader.writeUInt16LE(0, 28);
    const localRecord = Buffer.concat([localHeader, fileNameBuffer, fileData]);
    localFileBuffers.push(localRecord);
    fileRecords.push({
      name: file.name,
      offset: offset,
      crc: crc,
      fileNameLength: fileNameBuffer.length,
      fileDataLength: fileData.length
    });
    offset += localRecord.length;
  });
  const centralDirectoryBuffers = [];
  fileRecords.forEach(rec => {
    const fileNameBuffer = Buffer.from(rec.name);
    const centralHeader = Buffer.alloc(46);
    centralHeader.writeUInt32LE(0x02014b50, 0);
    centralHeader.writeUInt16LE(20, 4);
    centralHeader.writeUInt16LE(20, 6);
    centralHeader.writeUInt16LE(0, 8);
    centralHeader.writeUInt16LE(0, 10);
    centralHeader.writeUInt16LE(0, 12);
    centralHeader.writeUInt16LE(0, 14);
    centralHeader.writeUInt32LE(rec.crc, 16);
    centralHeader.writeUInt32LE(rec.fileDataLength, 20);
    centralHeader.writeUInt32LE(rec.fileDataLength, 24);
    centralHeader.writeUInt16LE(rec.fileNameLength, 28);
    centralHeader.writeUInt16LE(0, 30);
    centralHeader.writeUInt16LE(0, 32);
    centralHeader.writeUInt16LE(0, 34);
    centralHeader.writeUInt16LE(0, 36);
    centralHeader.writeUInt32LE(0, 38);
    centralHeader.writeUInt32LE(rec.offset, 42);
    centralDirectoryBuffers.push(Buffer.concat([centralHeader, fileNameBuffer]));
  });
  const centralDirectory = Buffer.concat(centralDirectoryBuffers);
  const centralDirectorySize = centralDirectory.length;
  const centralDirectoryOffset = offset;
  const eocdr = Buffer.alloc(22);
  eocdr.writeUInt32LE(0x06054b50, 0);
  eocdr.writeUInt16LE(0, 4);
  eocdr.writeUInt16LE(0, 6);
  eocdr.writeUInt16LE(fileRecords.length, 8);
  eocdr.writeUInt16LE(fileRecords.length, 10);
  eocdr.writeUInt32LE(centralDirectorySize, 12);
  eocdr.writeUInt32LE(centralDirectoryOffset, 16);
  eocdr.writeUInt16LE(0, 20);
  return Buffer.concat([...localFileBuffers, centralDirectory, eocdr]);
}

// Bulk download endpoint: accepts comma-separated file IDs via "ids"
app.get('/download/bulk', passwordMiddleware, async (req, res) => {
  try {
    let ids = [];
    if (req.query.ids) {
      ids = Array.isArray(req.query.ids)
        ? req.query.ids
        : req.query.ids.split(',');
    }
    if (ids.length === 0) {
      return res.redirect(`/?password=${req.query.password}`);
    }
    const zipFiles = [];
    for (let file of await File.find({ _id: { $in: ids } })) {
      const filePath = path.join(UPLOAD_DIR, file.filename);
      const encryptedData = fs.readFileSync(filePath);
      const decryptedData = decryptFile(encryptedData, file.iv);
      zipFiles.push({ name: file.originalname, data: decryptedData });
    }
    const zipBuffer = createZip(zipFiles);
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="files.zip"');
    res.send(zipBuffer);
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Bulk download failed', error: err.message });
  }
});

// Bulk upload endpoint (supports multiple files)
app.post('/upload', passwordMiddleware, (req, res) => {
  const contentType = req.headers['content-type'];
  const boundary = contentType && contentType.split('boundary=')[1];
  if (!boundary) return res.status(400).json({ message: 'Invalid form-data' });
  let body = Buffer.alloc(0);
  req.on('data', chunk => body = Buffer.concat([body, chunk]));
  req.on('end', async () => {
    try {
      const parts = body.toString('binary').split(`--${boundary}`);
      const fileUploads = [];
      parts.forEach(part => {
        if (part.indexOf('Content-Disposition') !== -1 && part.indexOf('filename="') !== -1) {
          const headerEndIndex = part.indexOf('\r\n\r\n');
          if (headerEndIndex === -1) return;
          const header = part.substring(0, headerEndIndex);
          const filenameMatch = header.match(/filename="(.+?)"/);
          if (!filenameMatch) return;
          const originalname = filenameMatch[1];
          let fileDataStr = part.substring(headerEndIndex + 4);
          fileDataStr = fileDataStr.replace(/\r\n--$/, '').trim();
          const fileData = Buffer.from(fileDataStr, 'binary');
          const { iv, encrypted } = encryptFile(fileData);
          const uniqueFilename = Date.now() + '-' + originalname;
          const filePath = path.join(UPLOAD_DIR, uniqueFilename);
          fs.writeFileSync(filePath, encrypted);
          fileUploads.push({ originalname, filename: uniqueFilename, iv });
        }
      });
      if (fileUploads.length > 0) {
        await File.insertMany(fileUploads);
      }
      res.redirect(`/?password=${req.query.password}`);
    } catch (err) {
      console.error(err);
      res.status(500).json({ message: 'Upload failed', error: err.message });
    }
  });
});

function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

app.get('/', passwordMiddleware, async (req, res) => {
  const password = req.query.password;
  const files = await File.find({}, 'originalname _id filename').sort({ uploadDate: -1 });

  // Build an array with file info including type (image or video)
  const galleryFiles = files.map(file => {
    const ext = path.extname(file.originalname).toLowerCase();
    const type = (['.mp4', '.webm', '.ogg', '.mov', '.avi', '.flv'].includes(ext)) ? 'video' : 'image';
    return {
      id: file._id,
      originalname: file.originalname,
      type: type,
      url: `/download/${file._id}?password=${password}&inline=true`,
      filename: file.filename
    };
  });

  // Generate gallery items HTML.
  // Each item gets data-index and data-id attributes plus a unified click handler.
  const galleryItems = galleryFiles.map((file, index) => {
    const filePath = path.join(UPLOAD_DIR, file.filename);
    let sizeStr = "";
    try {
      const stats = fs.statSync(filePath);
      sizeStr = formatBytes(stats.size);
    } catch (e) {
      sizeStr = "N/A";
    }
    let mediaTag = '';
    if (file.type === 'image') {
      mediaTag = `<img loading="lazy" src="${file.url}" alt="${file.originalname}">`;
    } else {
      mediaTag = `<video loading="lazy" src="${file.url}" muted playsinline preload="auto"></video>`;
    }
    return `<div class="gallery-item" data-index="${index}" data-id="${file.id}" onclick="handleGalleryItemClick(event, ${index}, '${file.id}')">
        <div class="image-box">
          ${mediaTag}
        </div>
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
  }).join('');

  const html = `<!DOCTYPE html>
  <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta name="viewport" content="width=device-width, initial-scale=1">
      <title>Image & Video Uploader & Downloader</title>
      <link rel="icon" href="favicon.ico" type="image/x-icon">
      <meta name="description" content="Upload and download your images and videos easily with our user-friendly platform.">
      <meta name="keywords" content="image uploader, video uploader, file downloader, media platform">
      <meta name="author" content="Bastian olai hauge wedaa">

      <style>
        /* Base dark theme */
        body {
          background: #202123;
          color: #E4E6EB;
          font-family: Arial, sans-serif;
          margin: 0;
          padding: 20px;
        }
        .container {
          max-width: 1200px;
          margin: auto;
          background: #2D2F31;
          padding: 20px;
          border-radius: 8px;
          box-shadow: 0 2px 8px rgba(0,0,0,0.5);
        }
        h1, h2 {
          color: #ffffff;
          text-align: center;
        }
        form.upload-form {
          margin-bottom: 20px;
          text-align: center;
        }
        input[type="file"] {
          display: block;
          margin: auto;
          margin-bottom: 10px;
          background: #3A3B3C;
          color: #ffffff;
          border: none;
          padding: 8px;
          border-radius: 4px;
          width: 90%;
          max-width: 400px;
        }
        button {
          background: #4A90E2;
          color: #ffffff;
          border: none;
          padding: 10px 20px;
          border-radius: 4px;
          cursor: pointer;
          font-size: 1em;
          margin: 5px;
        }
        button:hover {
          background: #357ABD;
        }
        .grid-options {
          text-align: center;
          margin-bottom: 20px;
        }
        .grid-options select {
          background: #3A3B3C;
          color: #ffffff;
          border: none;
          padding: 5px;
          border-radius: 4px;
          font-size: 1em;
        }
        .gallery {
          display: grid;
          gap: 10px;
          margin-top: 20px;
          grid-template-columns: repeat(3, 1fr);
        }
        .gallery-item {
          background: #3A3B3C;
          border-radius: 4px;
          position: relative;
          cursor: pointer;
          overflow: hidden;
          height: 250px;
          display: flex;
          flex-direction: column;
        }
        .gallery-item .image-box {
          flex: 8;
          overflow: hidden;
        }
        .gallery-item .image-box img,
        .gallery-item .image-box video {
          width: 100%;
          height: 100%;
          object-fit: cover;
          display: block;
        }
        .gallery-item .info-box {
          flex: 2;
          display: flex;
          align-items: center;
          justify-content: space-between;
          padding: 0 5px;
          background: rgba(0,0,0,0.7);
        }
        .gallery-item .file-details {
          color: #fff;
          font-size: 0.8em;
          overflow: hidden;
          white-space: nowrap;
          text-overflow: ellipsis;
        }
        .gallery-item .actions a {
          color: #4A90E2;
          text-decoration: none;
          margin-left: 5px;
          font-size: 0.8em;
        }
        /* Checkmark overlay when selected */
        .gallery-item.selected::after {
          content: "\\2713";
          position: absolute;
          top: 5px;
          right: 5px;
          font-size: 24px;
          color: #4A90E2;
          background: rgba(0, 0, 0, 0.6);
          padding: 4px;
          border-radius: 50%;
          z-index: 4;
        }
        .controls {
          text-align: center;
          margin-top: 20px;
        }
        /* Selection controls rendered only in select mode */
        #selectionControls {
          display: none;
        }
        /* Modal styles using viewport units for responsiveness */
        .modal {
          display: none;
          position: fixed;
          z-index: 1000;
          left: 0;
          top: 0;
          width: 100%;
          height: 100%;
          overflow: hidden;
          background-color: rgba(0,0,0,0.9);
        }
        .modal-content {
          position: relative;
          margin: auto;
          width: 90vw;
          height: 90vh;
          text-align: center;
        }
        .modal-media-container {
          width: 100%;
          height: calc(100% - 60px);
          display: flex;
          align-items: center;
          justify-content: center;
        }
        .modal-media-container img,
        .modal-media-container video {
          max-width: 100%;
          max-height: 100%;
          object-fit: contain;
        }
        .close {
          position: absolute;
          top: 10px;
          right: 25px;
          color: #fff;
          font-size: 35px;
          font-weight: bold;
          cursor: pointer;
        }
        .modal-actions {
          margin-top: 10px;
        }
        .modal-actions a {
          color: #4A90E2;
          text-decoration: none;
          margin: 0 10px;
          font-size: 1em;
        }
        .prev, .next {
          cursor: pointer;
          position: absolute;
          top: 50%;
          padding: 16px;
          color: #fff;
          font-weight: bold;
          font-size: 20px;
          transition: 0.3s;
          user-select: none;
          background: rgba(0,0,0,0.5);
          border: none;
        }
        .prev:hover, .next:hover {
          background: rgba(0,0,0,0.8);
        }
        .prev {
          left: 0;
          border-radius: 0 3px 3px 0;
        }
        .next {
          right: 0;
          border-radius: 3px 0 0 3px;
        }
        /* Responsive adjustments for mobile devices */
        @media screen and (max-width: 600px) {
          .gallery {
            grid-template-columns: repeat(2, 1fr);
          }
        }
          
      </style>
      <script>
        let currentIndex = 0;
        let selectMode = false;
        const galleryFiles = ${JSON.stringify(galleryFiles)};
        const password = "${password.toString()}";
  
        // Toggle Select Mode and show/hide the selection controls.
        function toggleSelectMode() {
          selectMode = !selectMode;
          const btn = document.getElementById('toggleSelectMode');
          btn.innerText = selectMode ? "Exit Select Mode" : "Enter Select Mode";
          document.getElementById('selectionControls').style.display = selectMode ? "block" : "none";
          if (!selectMode) {
            // Clear any selections when leaving select mode.
            document.querySelectorAll('.gallery-item.selected').forEach(item => {
              item.classList.remove('selected');
              const id = item.getAttribute('data-id');
              document.getElementById('cb-' + id).checked = false;
            });
          }
        }
  
        // Unified click handler for gallery items.
        function handleGalleryItemClick(event, index, fileId) {
          event.stopPropagation();
          if (selectMode) {
            toggleSelection(fileId);
          } else {
            openModal(event, index);
          }
        }
  
        // Toggle selection state on a single gallery item.
        function toggleSelection(fileId) {
          const galleryItem = document.querySelector('.gallery-item[data-id="' + fileId + '"]');
          const checkbox = document.getElementById('cb-' + fileId);
          if (checkbox.checked) {
            checkbox.checked = false;
            galleryItem.classList.remove('selected');
          } else {
            checkbox.checked = true;
            galleryItem.classList.add('selected');
          }
        }
  
        // Select all gallery items.
        function selectAllItems() {
          document.querySelectorAll('.gallery-item').forEach(item => {
            const id = item.getAttribute('data-id');
            item.classList.add('selected');
            document.getElementById('cb-' + id).checked = true;
          });
        }
  
        // Deselect all gallery items.
        function deselectAllItems() {
          document.querySelectorAll('.gallery-item').forEach(item => {
            const id = item.getAttribute('data-id');
            item.classList.remove('selected');
            document.getElementById('cb-' + id).checked = false;
          });
        }
  
        // Open modal for viewing a file.
        function openModal(event, index) {
          if (event.target.closest('.info-box')) {
            return;\
          }
          currentIndex = index;
          updateModal();
          updateButtons();
          document.getElementById('modal').style.display = "block";
        }
  
        function closeModal(event) {
          if (event.target.closest('.modal-media-container img, .modal-media-container video')) {
            return;
          }
            
          document.getElementById('modal').style.display = "none";
          const video = document.getElementById('modalVideo');
            if (video) {
              video.pause();
              video.currentTime = 0; // Reset to the beginning
            }
          currentIndex = -1;
          updateButtons();
        }
  
        // Update modal content based on the current index.
        function updateModal() {
          const file = galleryFiles[currentIndex];
          const container = document.getElementById('modalMediaContainer');
          if(file.type === 'image') {
            container.innerHTML = '<img src="' + file.url + '" alt="' + file.originalname + '">';
          } else {
            container.innerHTML = '<video src="' + file.url + '" controls preload="auto" autoplay playsinline  id="modalVideo">Your browser does not support the video tag.</video>';
          }
            
          document.getElementById('modalDownload').href = "/download/" + file.id + "?password=" + password;
          document.getElementById('modalDelete').href = "/delete/" + file.id + "?password=" + password;
        }
  
        // Modal navigation.
        function nextModal() {
          if(currentIndex < galleryFiles.length - 1) {
            currentIndex++;
            updateModal();
            updateButtons();
          }
        }
  
        function prevModal() {
          if(currentIndex > 0) {
            currentIndex--;
            updateModal();
            updateButtons();
          }
        }

        function updateButtons() {
          // Check if there is a next element
          if (currentIndex < galleryFiles.length - 1) {
            document.getElementById('nextButton').style.display = 'inline-block';
          } else {
            document.getElementById('nextButton').style.display = 'none';
          }

          // Check if there is a previous element
          if (currentIndex > 0) {
            document.getElementById('prevButton').style.display = 'inline-block';
          } else {
            document.getElementById('prevButton').style.display = 'none';
          }
        }
        
        // Helper to get the IDs of all selected items.
        function getCheckedIds() {
          const checkboxes = document.querySelectorAll('.gallery-item input[type="checkbox"]');
          const ids = [];
          checkboxes.forEach(cb => { if(cb.checked) ids.push(cb.value); });
          return ids;
        }
  
        // Bulk download: redirect to the bulk download endpoint with selected IDs.
        function bulkDownload() {
          const ids = getCheckedIds();
          if(ids.length === 0) {
            alert("No files selected for bulk download.");
            return;
          }
          window.location.href = "/download/bulk?password=" + password + "&ids=" + ids.join(",");
        }
  
        // Bulk delete: create and submit a form with the selected IDs.
        function bulkDelete() {
          const ids = getCheckedIds();
          if(ids.length === 0) {
            alert("No files selected for bulk delete.");
            return;
          }
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
            const cols = this.value;
            document.querySelector('.gallery').style.gridTemplateColumns = 'repeat(' + cols + ', 1fr)';
          });
        });

        document.getElementById('modal').addEventListener('click', function(event) {
          const mediaContainer = document.getElementById('modalMediaContainer');
          if (!mediaContainer.contains(event.target)) {
            closeModal(event);
          }
        });

      // Prevent closing the modal when clicking on the video or image
      document.getElementById('modalMediaContainer').addEventListener('click', function(event) {
        event.stopPropagation(); // Prevent the click from propagating to the modal background
      });
      </script>
    </head>
    <body>
      <div class="container">
        <h1>Image & Video Uploader & Downloader</h1>
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
          ${galleryItems}
        </div>
      </div>
      <!-- Modal for full-screen view -->
      <div id="modal" class="modal">
        <div class="modal-content">
          <span class="close" onclick="closeModal(event)">&times;</span>
          <button class="prev" onclick="prevModal()" id="prevButton" style="display: none;">&#10094;</button>
          <div id="modalMediaContainer" onclick="closeModal(event)"" class="modal-media-container"></div>
          <button class="next" onclick="nextModal()" id="nextButton" style="display: none;">&#10095;</button>
          <div class="modal-actions">
            <a id="modalDownload" href="">Download</a>
            <a id="modalDelete" href="" onclick="return confirm('Delete this file?')">Delete</a>
          </div>
        </div>
      </div>
    </body>
  </html>`;
  res.send(html);
});



app.listen(PORT, "0.0.0.0", () => console.log(`Server running on port ${PORT}`));

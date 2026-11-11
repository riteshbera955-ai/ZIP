const express = require('express');
const multer = require('multer');
const yauzl = require('yauzl');
const archiver = require('archiver');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

const DATA_DIR = process.env.DATA_DIR || '/var/data';
const TEMP_DIR = path.join(DATA_DIR, 'tmp-uploads');

const MAX_ZIP_BYTES = 100 * 1024 * 1024;
const MAX_BATCH_BYTES = 200 * 1024 * 1024;
const MAX_BATCH_FILES = 20;

const MAX_ENTRIES = 5000;
const MAX_TOTAL_EXPANDED = 300 * 1024 * 1024;
const MAX_SINGLE_FILE = 60 * 1024 * 1024;

const ALLOWED_EXTENSIONS = new Set([
    '.pdf',
    '.jpg',
    '.jpeg'
]);

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(TEMP_DIR, { recursive: true });

// Permanent database: old records remain intact.
const db = new Database(
    path.join(DATA_DIR, 'duplicates.sqlite3')
);

db.pragma('journal_mode = WAL');
db.pragma('busy_timeout = 5000');

db.exec(`
    CREATE TABLE IF NOT EXISTS seen_files (
        sha256 TEXT PRIMARY KEY,
        first_seen_utc TEXT NOT NULL
    )
`);

const insertHash = db.prepare(`
    INSERT OR IGNORE INTO seen_files
    (sha256, first_seen_utc)
    VALUES (?, ?)
`);

const hashExists = db.prepare(`
    SELECT 1 FROM seen_files WHERE sha256 = ?
`);

// Upload files to persistent disk temporarily.
const storage = multer.diskStorage({
    destination: (_req, _file, cb) => {
        cb(null, TEMP_DIR);
    },

    filename: (_req, file, cb) => {
        const filename =
            `${Date.now()}-${crypto.randomBytes(8).toString('hex')}.zip`;

        cb(null, filename);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: MAX_ZIP_BYTES,
        files: MAX_BATCH_FILES
    }
});

app.use(express.static(path.join(__dirname, 'public')));

function sha256(buffer) {
    return crypto
        .createHash('sha256')
        .update(buffer)
        .digest('hex');
}

function openZip(buffer) {
    return new Promise((resolve, reject) => {
        yauzl.fromBuffer(
            buffer,
            {
                lazyEntries: true,
                decodeStrings: true,
                autoClose: true,
                validateEntrySizes: true
            },
            (err, zip) => {
                if (err) reject(err);
                else resolve(zip);
            }
        );
    });
}

function readEntry(zip, entry) {
    return new Promise((resolve, reject) => {
        zip.openReadStream(entry, (err, stream) => {
            if (err) return reject(err);

            const chunks = [];
            let size = 0;

            stream.on('data', chunk => {
                size += chunk.length;

                if (size > MAX_SINGLE_FILE) {
                    stream.destroy(
                        new Error(
                            'An item inside the ZIP exceeds the 60 MB per-file limit.'
                        )
                    );
                } else {
                    chunks.push(chunk);
                }
            });

            stream.on('error', reject);

            stream.on('end', () => {
                resolve(Buffer.concat(chunks));
            });
        });
    });
}

function safeName(input, used) {
    let name = path.posix.basename(
        String(input).replace(/\\/g, '/')
    );

    name = name
        .replace(/[^a-zA-Z0-9._() -]/g, '_')
        .replace(/^[ .]+|[ .]+$/g, '') || 'file';

    const ext = path.extname(name);
    const stem = path.basename(name, ext);

    let candidate = name;
    let n = 2;

    while (used.has(candidate.toLowerCase())) {
        candidate = `${stem}_${n++}${ext}`;
    }

    used.add(candidate.toLowerCase());

    return candidate;
}

function makeZip(files) {
    return new Promise((resolve, reject) => {
        const chunks = [];

        const archive = archiver('zip', {
            zlib: { level: 3 }
        });

        archive.on('data', chunk => chunks.push(chunk));

        archive.on('warning', err => {
            if (err.code !== 'ENOENT') reject(err);
        });

        archive.on('error', reject);

        archive.on('end', () => {
            resolve(Buffer.concat(chunks));
        });

        for (const file of files) {
            archive.append(file.data, {
                name: file.name
            });
        }

        archive.finalize().catch(reject);
    });
}

// Prevent simultaneous requests from interfering with duplicate checks.
let queue = Promise.resolve();

function inQueue(fn) {
    const promise = queue.then(fn, fn);
    queue = promise.catch(() => {});
    return promise;
}

// Process one ZIP.
async function processZip(buffer) {
    const zip = await openZip(buffer);

    const output = [];
    const hashes = [];
    const seen = new Set();
    const used = new Set();

    let total = 0;
    let duplicates = 0;
    let ignored = 0;
    let expanded = 0;
    let entries = 0;

    await new Promise((resolve, reject) => {
        let done = false;

        const fail = err => {
            if (done) return;

            done = true;

            try {
                zip.close();
            } catch (_) {}

            reject(err);
        };

        zip.on('error', fail);

        zip.on('end', () => {
            if (!done) {
                done = true;
                resolve();
            }
        });

        zip.on('entry', async entry => {
            if (done) return;

            try {
                if (++entries > MAX_ENTRIES) {
                    throw new Error(
                        `ZIP contains more than ${MAX_ENTRIES} entries.`
                    );
                }

                if (/\/$/.test(entry.fileName)) {
                    return zip.readEntry();
                }

                const ext = path.extname(
                    entry.fileName
                ).toLowerCase();

                if (!ALLOWED_EXTENSIONS.has(ext)) {
                    ignored++;
                    return zip.readEntry();
                }

                total++;

                if (entry.uncompressedSize > MAX_SINGLE_FILE) {
                    ignored++;
                    return zip.readEntry();
                }

                expanded += entry.uncompressedSize;

                if (expanded > MAX_TOTAL_EXPANDED) {
                    throw new Error(
                        'ZIP expands beyond the 300 MB limit. Split it into smaller ZIPs.'
                    );
                }

                const data = await readEntry(zip, entry);
                const hash = sha256(data);

                if (hashExists.get(hash) || seen.has(hash)) {
                    duplicates++;
                } else {
                    seen.add(hash);
                    hashes.push(hash);

                    output.push({
                        name: safeName(entry.fileName, used),
                        data
                    });
                }

                zip.readEntry();

            } catch (err) {
                fail(err);
            }
        });

        zip.readEntry();
    });

    const outputBuffer = output.length
        ? await makeZip(output)
        : null;

    // Save new hashes only after this ZIP has been processed.
    const now = new Date().toISOString();

    db.transaction(items => {
        for (const hash of items) {
            insertHash.run(hash, now);
        }
    })(hashes);

    return {
        outputBuffer,

        stats: {
            totalFiles: total,
            duplicatesRemoved: duplicates,
            newUniqueFiles: output.length,
            ignoredFiles: ignored
        }
    };
}

function cleanFiles(files = []) {
    for (const file of files) {
        try {
            fs.unlinkSync(file.path);
        } catch (_) {}
    }
}

function safeBase(name) {
    return path
        .basename(name, path.extname(name))
        .replace(/[^a-zA-Z0-9_-]/g, '_')
        .slice(0, 50) || 'archive';
}

// Health check.
app.get('/health', (_req, res) => {
    res.json({
        status: 'ok',
        service: 'permanent-zip-duplicate-checker'
    });
});

// Database count.
app.get('/api/status', (_req, res) => {
    const count = db.prepare(
        'SELECT COUNT(*) AS count FROM seen_files'
    ).get().count;

    res.json({
        storedUniqueFiles: count
    });
});

// Existing single ZIP upload.
app.post(
    '/api/process',
    upload.single('zipfile'),
    async (req, res) => {

        if (!req.file) {
            return res.status(400).json({
                error: 'Please select a ZIP file.'
            });
        }

        if (!req.file.originalname.toLowerCase().endsWith('.zip')) {
            cleanFiles([req.file]);

            return res.status(400).json({
                error: 'Only .zip files are supported.'
            });
        }

        try {
            const result = await inQueue(async () => {
                return processZip(
                    fs.readFileSync(req.file.path)
                );
            });

            if (!result.outputBuffer) {
                return res.json({
                    message: 'No new PDF/JPG files found. All supported files were duplicates.',
                    stats: result.stats
                });
            }

            res.setHeader(
                'Content-Type',
                'application/zip'
            );

            res.setHeader(
                'Content-Disposition',
                `attachment; filename="unique_${safeBase(req.file.originalname)}.zip"`
            );

            res.setHeader(
                'X-Filter-Stats',
                Buffer.from(
                    JSON.stringify(result.stats)
                ).toString('base64')
            );

            return res.send(result.outputBuffer);

        } catch (err) {
            console.error('Single ZIP error:', err);

            return res.status(400).json({
                error: err.message || 'Could not process ZIP.'
            });

        } finally {
            cleanFiles([req.file]);
        }
    }
);

// Bulk ZIP upload.
app.post(
    '/api/bulk-process',
    upload.array('zipfiles', MAX_BATCH_FILES),
    async (req, res) => {

        const files = req.files || [];

        if (!files.length) {
            return res.status(400).json({
                error: 'Select at least one ZIP file.'
            });
        }

        const totalBytes = files.reduce(
            (total, file) => total + file.size,
            0
        );

        if (
            files.some(
                file => !file.originalname.toLowerCase().endsWith('.zip')
            )
        ) {
            cleanFiles(files);

            return res.status(400).json({
                error: 'Every selected file must be a .zip file.'
            });
        }

        if (totalBytes > MAX_BATCH_BYTES) {
            cleanFiles(files);

            return res.status(413).json({
                error: 'Combined ZIP size exceeds 200 MB. Select fewer or smaller ZIP files.'
            });
        }

        const tempOutput = path.join(
            TEMP_DIR,
            `bulk-${Date.now()}-${crypto.randomBytes(6).toString('hex')}.zip`
        );

        try {
            const result = await inQueue(async () => {

                const totals = {
                    zipCount: files.length,
                    totalFiles: 0,
                    duplicatesRemoved: 0,
                    newUniqueFiles: 0,
                    ignoredFiles: 0,
                    perZip: []
                };

                const master = archiver('zip', {
                    zlib: { level: 1 }
                });

                const out = fs.createWriteStream(tempOutput);

                const completed = new Promise((resolve, reject) => {
                    out.on('close', resolve);
                    out.on('error', reject);

                    master.on('error', reject);

                    master.on('warning', err => {
                        if (err.code !== 'ENOENT') reject(err);
                    });
                });

                master.pipe(out);

                // Process ZIP files sequentially.
                for (let i = 0; i < files.length; i++) {

                    const file = files[i];

                    const processed = await processZip(
                        fs.readFileSync(file.path)
                    );

                    const stat = {
                        zipName: file.originalname,
                        ...processed.stats
                    };

                    totals.perZip.push(stat);

                    for (const key of [
                        'totalFiles',
                        'duplicatesRemoved',
                        'newUniqueFiles',
                        'ignoredFiles'
                    ]) {
                        totals[key] += processed.stats[key];
                    }

                    if (processed.outputBuffer) {
                        master.append(
                            processed.outputBuffer,
                            {
                                name:
                                    `ZIP_${String(i + 1).padStart(2, '0')}_${safeBase(file.originalname)}_unique_files.zip`
                            }
                        );
                    }

                    processed.outputBuffer = null;
                }

                master.append(
                    Buffer.from(
                        JSON.stringify(totals, null, 2)
                    ),
                    {
                        name: 'BULK_SUMMARY.json'
                    }
                );

                await master.finalize();
                await completed;

                return totals;
            });

            res.setHeader(
                'Content-Type',
                'application/zip'
            );

            res.setHeader(
                'Content-Disposition',
                'attachment; filename="BULK_RESULT.zip"'
            );

            res.setHeader(
                'X-Bulk-Stats',
                Buffer.from(
                    JSON.stringify(result)
                ).toString('base64')
            );

            const stream = fs.createReadStream(tempOutput);

            stream.on('error', err => {
                console.error('Bulk download stream error:', err);

                if (!res.headersSent) {
                    res.status(500).end(
                        'Could not send result ZIP'
                    );
                } else {
                    res.destroy(err);
                }
            });

            stream.on('close', () => {
                try {
                    fs.unlinkSync(tempOutput);
                } catch (_) {}
            });

            stream.pipe(res);

        } catch (err) {
            console.error('Bulk ZIP error:', err);

            try {
                fs.unlinkSync(tempOutput);
            } catch (_) {}

            if (!res.headersSent) {
                res.status(400).json({
                    error: err.message || 'Bulk processing failed.'
                });
            }

        } finally {
            cleanFiles(files);
        }
    }
);

// Error handling.
app.use((err, _req, res, _next) => {

    if (err instanceof multer.MulterError) {

        const status =
            err.code === 'LIMIT_FILE_SIZE' ||
            err.code === 'LIMIT_FILE_COUNT'
                ? 413
                : 400;

        const message =
            err.code === 'LIMIT_FILE_SIZE'
                ? 'One ZIP exceeds the 100 MB limit.'
                : err.code === 'LIMIT_FILE_COUNT'
                    ? 'Maximum 20 ZIP files are allowed.'
                    : err.message;

        return res.status(status).json({
            error: message
        });
    }

    console.error(err);

    return res.status(500).json({
        error: 'Server error. Check Render logs.'
    });
});

// Start server.
app.listen(PORT, () => {
    console.log(
        `ZIP checker listening on ${PORT}; database: ${path.join(DATA_DIR, 'duplicates.sqlite3')}`
    );
});

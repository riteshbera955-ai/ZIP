const express = require("express");
const multer = require("multer");
const yauzl = require("yauzl");
const archiver = require("archiver");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR || "/var/data";

const MAX_UPLOAD_BYTES = 40 * 1024 * 1024;
const MAX_ENTRIES = 5000;
const MAX_TOTAL_EXPANDED = 300 * 1024 * 1024;

const ALLOWED_EXTENSIONS = new Set([
    ".pdf",
    ".jpg",
    ".jpeg"
]);

fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(
    path.join(DATA_DIR, "duplicates.sqlite3")
);

db.pragma("journal_mode = WAL");
db.pragma("busy_timeout = 5000");

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

const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: MAX_UPLOAD_BYTES,
        files: 1
    }
});

app.use(express.static(
    path.join(__dirname, "public")
));

function sha256(buffer) {
    return crypto
        .createHash("sha256")
        .update(buffer)
        .digest("hex");
}

function openZip(buffer) {
    return new Promise((resolve, reject) => {
        yauzl.fromBuffer(
            buffer,
            {
                lazyEntries: true,
                decodeStrings: true,
                autoClose: true
            },
            (err, zipfile) => {
                if (err) reject(err);
                else resolve(zipfile);
            }
        );
    });
}

function readEntry(zipfile, entry) {
    return new Promise((resolve, reject) => {
        zipfile.openReadStream(entry, (err, stream) => {
            if (err) return reject(err);

            const chunks = [];
            let bytes = 0;

            stream.on("data", chunk => {
                bytes += chunk.length;

                if (bytes > 60 * 1024 * 1024) {
                    stream.destroy(
                        new Error("File exceeds size limit.")
                    );
                    return;
                }

                chunks.push(chunk);
            });

            stream.on("error", reject);

            stream.on("end", () => {
                resolve(Buffer.concat(chunks));
            });
        });
    });
}

function safeOutputName(originalName, usedNames) {
    const normalized = String(originalName)
        .replace(/\\/g, "/");

    let name = path.posix.basename(normalized);

    name = name
        .replace(/[^a-zA-Z0-9._() -]/g, "_")
        .replace(/^[ .]+|[ .]+$/g, "");

    if (!name) name = "file";

    const ext = path.extname(name);
    const stem = path.basename(name, ext);

    let candidate = name;
    let index = 2;

    while (usedNames.has(candidate.toLowerCase())) {
        candidate = `${stem}_${index}${ext}`;
        index++;
    }

    usedNames.add(candidate.toLowerCase());

    return candidate;
}

function buildZip(files) {
    return new Promise((resolve, reject) => {
        const chunks = [];

        const archive = archiver("zip", {
            zlib: { level: 6 }
        });

        archive.on("data", chunk => {
            chunks.push(chunk);
        });

        archive.on("warning", err => {
            if (err.code !== "ENOENT") reject(err);
        });

        archive.on("error", reject);

        archive.on("end", () => {
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

// Prevent simultaneous uploads from racing.
let processingQueue = Promise.resolve();

function serializeProcessing(task) {
    const result = processingQueue.then(task, task);

    processingQueue = result.catch(() => {});

    return result;
}

async function processZip(zipBuffer) {
    const zipfile = await openZip(zipBuffer);

    const outputFiles = [];
    const hashesToSave = [];
    const hashesInCurrentZip = new Set();
    const usedNames = new Set();

    let supportedFiles = 0;
    let duplicateFiles = 0;
    let ignoredFiles = 0;
    let expandedBytes = 0;
    let entryCount = 0;

    await new Promise((resolve, reject) => {
        let finished = false;

        const fail = error => {
            if (finished) return;

            finished = true;

            try {
                zipfile.close();
            } catch (_) {}

            reject(error);
        };

        zipfile.on("error", fail);

        zipfile.on("end", () => {
            if (!finished) {
                finished = true;
                resolve();
            }
        });

        zipfile.on("entry", async entry => {
            if (finished) return;

            try {
                entryCount++;

                if (entryCount > MAX_ENTRIES) {
                    throw new Error(
                        "ZIP contains too many files."
                    );
                }

                if (/\/$/.test(entry.fileName)) {
                    zipfile.readEntry();
                    return;
                }

                const extension = path
                    .extname(entry.fileName)
                    .toLowerCase();

                if (!ALLOWED_EXTENSIONS.has(extension)) {
                    ignoredFiles++;
                    zipfile.readEntry();
                    return;
                }

                supportedFiles++;

                if (entry.uncompressedSize > 60 * 1024 * 1024) {
                    ignoredFiles++;
                    zipfile.readEntry();
                    return;
                }

                expandedBytes += entry.uncompressedSize;

                if (expandedBytes > MAX_TOTAL_EXPANDED) {
                    throw new Error(
                        "ZIP expands beyond 300 MB. Split it into smaller ZIP files."
                    );
                }

                const data = await readEntry(zipfile, entry);

                const digest = sha256(data);

                const alreadyInDatabase =
                    Boolean(hashExists.get(digest));

                const repeatedInThisZip =
                    hashesInCurrentZip.has(digest);

                if (
                    alreadyInDatabase ||
                    repeatedInThisZip
                ) {
                    duplicateFiles++;
                } else {
                    hashesInCurrentZip.add(digest);

                    hashesToSave.push(digest);

                    outputFiles.push({
                        name: safeOutputName(
                            entry.fileName,
                            usedNames
                        ),
                        data
                    });
                }

                zipfile.readEntry();

            } catch (error) {
                fail(error);
            }
        });

        zipfile.readEntry();
    });

    const outputBuffer = outputFiles.length
        ? await buildZip(outputFiles)
        : null;

    const timestamp = new Date().toISOString();

    const saveHashes = db.transaction(items => {
        for (const digest of items) {
            insertHash.run(digest, timestamp);
        }
    });

    saveHashes(hashesToSave);

    return {
        outputBuffer,

        stats: {
            totalFiles: supportedFiles,
            duplicatesRemoved: duplicateFiles,
            newUniqueFiles: outputFiles.length,
            ignoredFiles,
            outputFileCount: outputFiles.length
        }
    };
}

// Health check
app.get("/health", (req, res) => {
    res.json({
        status: "ok",
        service: "permanent-zip-checker"
    });
});

// Database status
app.get("/api/status", (req, res) => {
    const row = db.prepare(
        "SELECT COUNT(*) AS count FROM seen_files"
    ).get();

    res.json({
        storedUniqueFiles: row.count
    });
});

// ZIP processing
app.post(
    "/api/process",
    upload.single("zipfile"),
    async (req, res) => {

        if (!req.file) {
            return res.status(400).json({
                error: "Please select a ZIP file."
            });
        }

        if (
            !req.file.originalname
                .toLowerCase()
                .endsWith(".zip")
        ) {
            return res.status(400).json({
                error: "Only ZIP files are supported."
            });
        }

        try {
            const result = await serializeProcessing(
                () => processZip(req.file.buffer)
            );

            if (result.stats.newUniqueFiles === 0) {
                return res.json({
                    message: "No new PDF/JPG files found.",
                    stats: result.stats
                });
            }

            const baseName = path.basename(
                req.file.originalname,
                path.extname(req.file.originalname)
            )
            .replace(/[^a-zA-Z0-9_-]/g, "_")
            .slice(0, 60) || "archive";

            const outputName = `unique_${baseName}.zip`;

            res.setHeader(
                "Content-Type",
                "application/zip"
            );

            res.setHeader(
                "Content-Disposition",
                `attachment; filename="${outputName}"`
            );

            res.setHeader(
                "X-Filter-Stats",
                Buffer.from(
                    JSON.stringify(result.stats)
                ).toString("base64")
            );

            return res.send(result.outputBuffer);

        } catch (error) {
            console.error(
                "ZIP processing failed:",
                error.message
            );

            return res.status(400).json({
                error: error.message ||
                    "Could not process ZIP."
            });
        }
    }
);

// Error handler
app.use((error, req, res, next) => {

    if (
        error instanceof multer.MulterError &&
        error.code === "LIMIT_FILE_SIZE"
    ) {
        return res.status(413).json({
            error: "ZIP upload limit is 40 MB."
        });
    }

    console.error(error);

    res.status(500).json({
        error: "Server error. Check Render logs."
    });
});

app.listen(PORT, () => {
    console.log(
        `ZIP Checker running on port ${PORT}`
    );

    console.log(
        `Database: ${path.join(DATA_DIR, "duplicates.sqlite3")}`
    );
});

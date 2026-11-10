"use strict";

const express = require("express");
const multer = require("multer");
const yauzl = require("yauzl");
const archiver = require("archiver");
const Database = require("better-sqlite3");
const crypto = require("crypto");
const path = require("path");
const fs = require("fs");

const app = express();

// ==========================================
// CONFIGURATION
// ==========================================

const PORT = process.env.PORT || 3000;

const DATA_DIR = process.env.DATA_DIR || "/var/data";

const MAX_UPLOAD_SIZE = 40 * 1024 * 1024;
const MAX_FILE_SIZE = 60 * 1024 * 1024;
const MAX_EXPANDED_SIZE = 300 * 1024 * 1024;
const MAX_ENTRIES = 5000;

const ALLOWED_ORIGINS = [
    "https://zipchecker.netlify.app",
    "http://localhost:3000"
];

// ==========================================
// CORS CONFIGURATION
// ==========================================

app.use((req, res, next) => {

    const origin = req.headers.origin;

    if (ALLOWED_ORIGINS.includes(origin)) {
        res.setHeader(
            "Access-Control-Allow-Origin",
            origin
        );
    }

    res.setHeader("Vary", "Origin");

    res.setHeader(
        "Access-Control-Allow-Methods",
        "GET, POST, OPTIONS"
    );

    res.setHeader(
        "Access-Control-Allow-Headers",
        "Content-Type"
    );

    res.setHeader(
        "Access-Control-Expose-Headers",
        "Content-Disposition, X-Unique-Files, X-Duplicate-Files"
    );

    if (req.method === "OPTIONS") {
        return res.sendStatus(204);
    }

    next();
});

// ==========================================
// DATABASE DIRECTORY
// ==========================================

try {

    fs.mkdirSync(DATA_DIR, {
        recursive: true
    });

} catch (error) {

    console.error(
        "DATABASE DIRECTORY ERROR:",
        error
    );

    process.exit(1);
}

// ==========================================
// DATABASE CONNECTION
// ==========================================

const databasePath = path.join(
    DATA_DIR,
    "duplicates.sqlite3"
);

const db = new Database(databasePath);

db.pragma("journal_mode = WAL");
db.pragma("busy_timeout = 5000");

// ==========================================
// CREATE DATABASE TABLE
// ==========================================

db.exec(`
    CREATE TABLE IF NOT EXISTS seen_files (
        sha256 TEXT PRIMARY KEY,
        filename TEXT,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP
    );
`);

// ==========================================
// AUTOMATIC DATABASE MIGRATION
// ==========================================

// Read existing database columns.

const columns = db.pragma(
    "table_info(seen_files)"
);

const columnNames = columns.map(
    column => column.name
);

// SHA-256 column must exist.

if (!columnNames.includes("sha256")) {

    throw new Error(
        "Database schema error: sha256 column is missing."
    );

}

// Add filename column if missing.

if (!columnNames.includes("filename")) {

    db.exec(`
        ALTER TABLE seen_files
        ADD COLUMN filename TEXT
    `);

    console.log(
        "Database Migration: filename column added."
    );

}

// Add first_seen column if missing.

if (!columnNames.includes("first_seen")) {

    db.exec(`
        ALTER TABLE seen_files
        ADD COLUMN first_seen TEXT
        DEFAULT CURRENT_TIMESTAMP
    `);

    console.log(
        "Database Migration: first_seen column added."
    );

}

console.log(
    "Database migration completed."
);

// ==========================================
// DATABASE QUERIES
// ==========================================

const findHash = db.prepare(`
    SELECT 1
    FROM seen_files
    WHERE sha256 = ?
    LIMIT 1
`);

const insertHash = db.prepare(`
    INSERT OR IGNORE INTO seen_files (
        sha256,
        filename
    )
    VALUES (?, ?)
`);

const getTotalFiles = db.prepare(`
    SELECT COUNT(*) AS total
    FROM seen_files
`);

// ==========================================
// MULTER UPLOAD CONFIGURATION
// ==========================================

const upload = multer({

    storage: multer.memoryStorage(),

    limits: {
        fileSize: MAX_UPLOAD_SIZE,
        files: 1
    },

    fileFilter: (req, file, callback) => {

        const extension = path.extname(
            file.originalname
        ).toLowerCase();

        if (extension !== ".zip") {

            return callback(
                new Error("Only ZIP files are allowed.")
            );

        }

        callback(null, true);

    }

});

// ==========================================
// HEALTH CHECK
// ==========================================

app.get("/health", (req, res) => {

    res.json({

        status: "ok",

        service: "permanent-zip-duplicate-checker"

    });

});

// ==========================================
// DATABASE STATUS API
// ==========================================

app.get("/api/status", (req, res) => {

    try {

        const result = getTotalFiles.get();

        res.json({

            status: "ok",

            totalUniqueFiles: result.total

        });

    } catch (error) {

        console.error(
            "DATABASE STATUS ERROR:",
            error
        );

        res.status(500).json({

            error: "Unable to read database status."

        });

    }

});

// ==========================================
// ZIP PROCESSOR
// ==========================================

function processZip(buffer) {

    return new Promise((resolve, reject) => {

        const uniqueFiles = [];

        const pendingHashes = new Map();

        const currentHashes = new Set();

        let entryCount = 0;
        let duplicateCount = 0;
        let ignoredCount = 0;
        let expandedSize = 0;

        let finished = false;

        let zipfile = null;

        function fail(error) {

            if (finished) return;

            finished = true;

            if (zipfile) {

                try {
                    zipfile.close();
                } catch (_) {}

            }

            reject(error);

        }

        function complete() {

            if (finished) return;

            finished = true;

            resolve({

                uniqueFiles,
                pendingHashes,

                uniqueCount: uniqueFiles.length,

                duplicateCount,
                ignoredCount,
                totalEntries: entryCount

            });

        }

        function nextEntry() {

            if (!finished && zipfile) {
                zipfile.readEntry();
            }

        }

        yauzl.fromBuffer(

            buffer,

            {
                lazyEntries: true,
                autoClose: true,
                validateEntrySizes: true
            },

            (error, openedZip) => {

                if (error) {
                    return fail(error);
                }

                zipfile = openedZip;

                zipfile.on("error", fail);

                zipfile.on("end", complete);

                zipfile.on("entry", entry => {

                    if (finished) return;

                    (async () => {

                        entryCount++;

                        if (entryCount > MAX_ENTRIES) {

                            throw new Error(
                                "ZIP contains more than 5000 entries."
                            );

                        }

                        const filename =
                            entry.fileName.replace(/\\/g, "/");

                        // Ignore directories.

                        if (filename.endsWith("/")) {

                            return nextEntry();

                        }

                        // Prevent unsafe paths.

                        const parts = filename.split("/");

                        if (
                            filename.startsWith("/") ||
                            parts.includes("..") ||
                            parts.includes("")
                        ) {

                            ignoredCount++;

                            return nextEntry();

                        }

                        // Only PDF, JPG and JPEG.

                        const extension =
                            path.extname(filename).toLowerCase();

                        if (
                            ![
                                ".pdf",
                                ".jpg",
                                ".jpeg"
                            ].includes(extension)
                        ) {

                            ignoredCount++;

                            return nextEntry();

                        }

                        if (
                            entry.uncompressedSize >
                            MAX_FILE_SIZE
                        ) {

                            throw new Error(
                                "A file exceeds the 60 MB limit."
                            );

                        }

                        expandedSize +=
                            entry.uncompressedSize;

                        if (
                            expandedSize >
                            MAX_EXPANDED_SIZE
                        ) {

                            throw new Error(
                                "Expanded ZIP contents exceed 300 MB."
                            );

                        }

                        // Read file from ZIP.

                        const fileBuffer =
                            await new Promise(
                                (resolveRead, rejectRead) => {

                                    zipfile.openReadStream(
                                        entry,
                                        (streamError, stream) => {

                                            if (streamError) {

                                                return rejectRead(
                                                    streamError
                                                );

                                            }

                                            const chunks = [];

                                            let size = 0;

                                            stream.on(
                                                "data",
                                                chunk => {

                                                    size += chunk.length;

                                                    if (
                                                        size >
                                                        MAX_FILE_SIZE
                                                    ) {

                                                        stream.destroy(
                                                            new Error(
                                                                "File size limit exceeded."
                                                            )
                                                        );

                                                        return;

                                                    }

                                                    chunks.push(chunk);

                                                }
                                            );

                                            stream.on(
                                                "error",
                                                rejectRead
                                            );

                                            stream.on(
                                                "end",
                                                () => {

                                                    resolveRead(
                                                        Buffer.concat(chunks)
                                                    );

                                                }
                                            );

                                        }
                                    );

                                }
                            );

                        if (
                            fileBuffer.length !==
                            entry.uncompressedSize
                        ) {

                            throw new Error(
                                "ZIP entry size validation failed."
                            );

                        }

                        // Generate SHA-256 hash.

                        const hash = crypto
                            .createHash("sha256")
                            .update(fileBuffer)
                            .digest("hex");

                        // Check current ZIP and old database.

                        if (
                            currentHashes.has(hash) ||
                            findHash.get(hash)
                        ) {

                            duplicateCount++;

                        } else {

                            currentHashes.add(hash);

                            pendingHashes.set(
                                hash,
                                path.basename(filename)
                            );

                            uniqueFiles.push({

                                name: filename,

                                buffer: fileBuffer

                            });

                        }

                        nextEntry();

                    })().catch(fail);

                });

                zipfile.readEntry();

            }

        );

    });

}

// ==========================================
// SERIAL PROCESSING QUEUE
// ==========================================

let processingQueue = Promise.resolve();

function enqueueProcessing(task) {

    const result = processingQueue.then(task);

    processingQueue = result.catch(() => {});

    return result;

}

// ==========================================
// ZIP PROCESS API
// ==========================================

app.post(
    "/api/process",
    upload.single("zipFile"),
    async (req, res) => {

        try {

            if (!req.file) {

                return res.status(400).json({

                    error: "Please upload a ZIP file."

                });

            }

            await enqueueProcessing(async () => {

                console.log(
                    "Processing:",
                    req.file.originalname
                );

                // Process ZIP.

                const result = await processZip(
                    req.file.buffer
                );

                console.log(
                    "Unique files:",
                    result.uniqueCount
                );

                console.log(
                    "Duplicate files:",
                    result.duplicateCount
                );

                // ==================================
                // CREATE OUTPUT ZIP
                // ==================================

                const outputBuffer =
                    await new Promise(
                        (resolveArchive, rejectArchive) => {

                            const archive = archiver(
                                "zip",
                                {
                                    zlib: {
                                        level: 6
                                    }
                                }
                            );

                            const chunks = [];

                            archive.on(
                                "data",
                                chunk => {
                                    chunks.push(chunk);
                                }
                            );

                            archive.on(
                                "error",
                                rejectArchive
                            );

                            archive.on(
                                "end",
                                () => {

                                    resolveArchive(
                                        Buffer.concat(chunks)
                                    );

                                }
                            );

                            for (
                                const file of result.uniqueFiles
                            ) {

                                archive.append(
                                    file.buffer,
                                    {
                                        name: file.name
                                    }
                                );

                            }

                            archive.finalize().catch(
                                rejectArchive
                            );

                        }
                    );

                // ==================================
                // SAVE HASHES AFTER ZIP CREATION
                // ==================================

                const saveHashes = db.transaction(() => {

                    for (
                        const [hash, filename]
                        of result.pendingHashes
                    ) {

                        insertHash.run(
                            hash,
                            filename
                        );

                    }

                });

                saveHashes();

                // ==================================
                // SEND DOWNLOAD
                // ==================================

                res.setHeader(
                    "Content-Type",
                    "application/zip"
                );

                res.setHeader(
                    "Content-Disposition",
                    'attachment; filename="unique_files.zip"'
                );

                res.setHeader(
                    "X-Unique-Files",
                    String(result.uniqueCount)
                );

                res.setHeader(
                    "X-Duplicate-Files",
                    String(result.duplicateCount)
                );

                res.send(outputBuffer);

                console.log(
                    "ZIP processing completed."
                );

            });

        } catch (error) {

            console.error(
                "PROCESSING ERROR:",
                error
            );

            if (!res.headersSent) {

                res.status(500).json({

                    error:
                        error.message ||
                        "ZIP processing failed."

                });

            }

        }

    }
);

// ==========================================
// ERROR HANDLER
// ==========================================

app.use((error, req, res, next) => {

    console.error(
        "SERVER ERROR:",
        error
    );

    if (res.headersSent) {
        return next(error);
    }

    res.status(400).json({

        error:
            error.message ||
            "Upload failed."

    });

});

// ==========================================
// START SERVER
// ==========================================

app.listen(PORT, "0.0.0.0", () => {

    console.log(
        "ZIP Duplicate Checker Started"
    );

    console.log(
        "PORT:",
        PORT
    );

    console.log(
        "DATABASE:",
        databasePath
    );

    console.log(
        "FRONTEND:",
        ALLOWED_ORIGINS[0]
    );

});

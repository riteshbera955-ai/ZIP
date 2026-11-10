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

// ======================================
// CONFIGURATION
// ======================================

const PORT = process.env.PORT || 3000;

const DATA_DIR = process.env.DATA_DIR || "/var/data";

const MAX_UPLOAD_SIZE = 40 * 1024 * 1024;

const MAX_EXPANDED_SIZE = 300 * 1024 * 1024;

const MAX_FILE_SIZE = 60 * 1024 * 1024;

const MAX_ENTRIES = 5000;

const ALLOWED_ORIGIN =
    "https://zipchecker.netlify.app";

// ======================================
// CORS CONFIGURATION
// ======================================

app.use((req, res, next) => {

    const origin = req.headers.origin;

    if (
        origin === ALLOWED_ORIGIN ||
        origin === "http://localhost:3000"
    ) {
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

// ======================================
// DATABASE SETUP
// ======================================

// IMPORTANT:
// Render Persistent Disk must be mounted
// at /var/data before starting the service.

try {

    fs.mkdirSync(DATA_DIR, {
        recursive: true
    });

} catch (error) {

    console.error("DATA DIRECTORY ERROR:", error);

    console.error(
        "Attach a writable Render Persistent Disk at:",
        DATA_DIR
    );

    process.exit(1);
}

const databasePath = path.join(
    DATA_DIR,
    "duplicates.sqlite3"
);

const db = new Database(databasePath);

db.pragma("journal_mode = WAL");

db.pragma("busy_timeout = 5000");

db.exec(`
    CREATE TABLE IF NOT EXISTS seen_files (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sha256 TEXT NOT NULL UNIQUE,
        filename TEXT NOT NULL,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP
    );
`);

const findHash = db.prepare(`
    SELECT id
    FROM seen_files
    WHERE sha256 = ?
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

// ======================================
// MULTER UPLOAD CONFIGURATION
// ======================================

const storage = multer.memoryStorage();

const upload = multer({

    storage: storage,

    limits: {
        fileSize: MAX_UPLOAD_SIZE,
        files: 1
    },

    fileFilter: (req, file, callback) => {

        if (
            path.extname(file.originalname).toLowerCase()
            !== ".zip"
        ) {
            return callback(
                new Error("Only ZIP files are allowed.")
            );
        }

        callback(null, true);
    }

});

// ======================================
// HEALTH CHECK
// ======================================

app.get("/health", (req, res) => {

    res.json({
        status: "ok",
        service: "permanent-zip-duplicate-checker"
    });

});

// ======================================
// DATABASE STATUS
// ======================================

app.get("/api/status", (req, res) => {

    try {

        const result = getTotalFiles.get();

        res.json({

            status: "ok",

            totalUniqueFiles: result.total

        });

    } catch (error) {

        console.error(error);

        res.status(500).json({

            error: "Unable to read database status."

        });

    }

});

// ======================================
// ZIP FILE PROCESSOR
// ======================================

function processZip(buffer) {

    return new Promise((resolve, reject) => {

        const uniqueFiles = [];

        let entryCount = 0;

        let expandedSize = 0;

        let duplicateCount = 0;

        let ignoredCount = 0;

        let finished = false;

        let processing = false;

        let zipfile;

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

                totalEntries: entryCount,

                uniqueCount: uniqueFiles.length,

                duplicateCount,

                ignoredCount,

                expandedSize

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

                zipfile.on("entry", (entry) => {

                    if (finished || processing) return;

                    processing = true;

                    (async () => {

                        entryCount++;

                        if (entryCount > MAX_ENTRIES) {

                            throw new Error(
                                "ZIP contains too many files. Maximum: 5000."
                            );

                        }

                        const originalName =
                            entry.fileName.replace(/\\/g, "/");

                        // Ignore directory entries.

                        if (originalName.endsWith("/")) {

                            processing = false;

                            return nextEntry();

                        }

                        // Prevent unsafe ZIP paths.

                        const parts = originalName.split("/");

                        if (
                            originalName.startsWith("/") ||
                            parts.includes("..") ||
                            parts.includes("")
                        ) {

                            ignoredCount++;

                            processing = false;

                            return nextEntry();

                        }

                        const extension = path.extname(
                            originalName
                        ).toLowerCase();

                        if (
                            ![".pdf", ".jpg", ".jpeg"].includes(extension)
                        ) {

                            ignoredCount++;

                            processing = false;

                            return nextEntry();

                        }

                        if (
                            entry.uncompressedSize > MAX_FILE_SIZE
                        ) {

                            throw new Error(
                                "A file exceeds the 60 MB limit."
                            );

                        }

                        expandedSize += entry.uncompressedSize;

                        if (
                            expandedSize > MAX_EXPANDED_SIZE
                        ) {

                            throw new Error(
                                "Expanded ZIP contents exceed 300 MB."
                            );

                        }

                        // Read ZIP entry.

                        const fileBuffer = await new Promise(
                            (resolveRead, rejectRead) => {

                                zipfile.openReadStream(
                                    entry,
                                    (streamError, stream) => {

                                        if (streamError) {
                                            return rejectRead(streamError);
                                        }

                                        const chunks = [];

                                        let size = 0;

                                        stream.on("data", chunk => {

                                            size += chunk.length;

                                            if (size > MAX_FILE_SIZE) {

                                                stream.destroy(
                                                    new Error(
                                                        "File size limit exceeded."
                                                    )
                                                );

                                                return;

                                            }

                                            chunks.push(chunk);

                                        });

                                        stream.on("error", rejectRead);

                                        stream.on("end", () => {

                                            resolveRead(
                                                Buffer.concat(chunks)
                                            );

                                        });

                                    }
                                );

                            }
                        );

                        if (
                            fileBuffer.length !== entry.uncompressedSize
                        ) {

                            throw new Error(
                                "ZIP entry size validation failed."
                            );

                        }

                        // SHA-256 fingerprint.

                        const hash = crypto
                            .createHash("sha256")
                            .update(fileBuffer)
                            .digest("hex");

                        // Check permanent database.

                        const existing = findHash.get(hash);

                        if (existing) {

                            duplicateCount++;

                        } else {

                            // Save fingerprint permanently.

                            const insertResult = insertHash.run(
                                hash,
                                path.basename(originalName)
                            );

                            if (insertResult.changes > 0) {

                                uniqueFiles.push({

                                    name: originalName,

                                    buffer: fileBuffer

                                });

                            } else {

                                duplicateCount++;

                            }

                        }

                        processing = false;

                        nextEntry();

                    })().catch(fail);

                });

                zipfile.readEntry();

            }
        );

    });

}

// ======================================
// ZIP PROCESS API
// ======================================

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

            console.log(
                "Processing ZIP:",
                req.file.originalname
            );

            const result = await processZip(
                req.file.buffer
            );

            console.log("ZIP Processing Complete");

            console.log(
                "Unique files:",
                result.uniqueCount
            );

            console.log(
                "Duplicates:",
                result.duplicateCount
            );

            // Create output ZIP.

            const archive = archiver("zip", {

                zlib: {
                    level: 6
                }

            });

            archive.on("warning", (error) => {

                console.warn("ZIP WARNING:", error);

            });

            archive.on("error", (error) => {

                console.error("ARCHIVE ERROR:", error);

                if (!res.headersSent) {

                    res.status(500).json({

                        error: "Unable to create output ZIP."

                    });

                } else {

                    res.destroy(error);

                }

            });

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

            archive.pipe(res);

            for (const file of result.uniqueFiles) {

                archive.append(file.buffer, {

                    name: file.name

                });

            }

            await archive.finalize();

        } catch (error) {

            console.error(
                "PROCESSING ERROR:",
                error
            );

            if (!res.headersSent) {

                res.status(500).json({

                    error: error.message ||
                        "ZIP processing failed."

                });

            } else {

                res.destroy(error);

            }

        }

    }
);

// ======================================
// MULTER ERROR HANDLER
// ======================================

app.use((error, req, res, next) => {

    console.error("UPLOAD ERROR:", error);

    if (res.headersSent) {
        return next(error);
    }

    res.status(400).json({

        error: error.message ||
            "Upload failed."

    });

});

// ======================================
// 404 HANDLER
// ======================================

app.use((req, res) => {

    res.status(404).json({

        error: "API endpoint not found."

    });

});

// ======================================
// START SERVER
// ======================================

app.listen(PORT, () => {

    console.log(
        `ZIP Checker running on port ${PORT}`
    );

    console.log(
        `Database location: ${databasePath}`
    );

    console.log(
        `Frontend: ${ALLOWED_ORIGIN}`
    );

});

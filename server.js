const express = require("express");
const cors = require("cors");
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
const TEMP_DIR = path.join(DATA_DIR, "tmp-uploads");

const MAX_ZIP_SIZE = 100 * 1024 * 1024;
const MAX_BATCH_SIZE = 200 * 1024 * 1024;
const MAX_BATCH_FILES = 20;

const MAX_ENTRIES = 5000;
const MAX_SINGLE_FILE = 60 * 1024 * 1024;
const MAX_EXPANDED_SIZE = 300 * 1024 * 1024;

fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(TEMP_DIR, { recursive: true });

/* =========================
   CORS
========================= */

app.use(cors({
    origin: [
        "https://zipchecker.netlify.app"
    ],
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"]
}));

app.use(express.static(path.join(__dirname, "public")));

/* =========================
   DATABASE
========================= */

const DB_PATH = path.join(
    DATA_DIR,
    "duplicates.sqlite3"
);

const db = new Database(DB_PATH);

db.pragma("journal_mode = WAL");
db.pragma("busy_timeout = 5000");

/*
 IMPORTANT:
 Existing file_fingerprints table is preserved.
 No old records are deleted.
*/

db.exec(`
    CREATE TABLE IF NOT EXISTS file_fingerprints (
        sha256 TEXT PRIMARY KEY,
        filename TEXT,
        first_seen TEXT DEFAULT CURRENT_TIMESTAMP
    )
`);

const hashExists = db.prepare(`
    SELECT 1
    FROM file_fingerprints
    WHERE sha256 = ?
`);

const insertHash = db.prepare(`
    INSERT OR IGNORE INTO file_fingerprints
    (sha256, filename, first_seen)
    VALUES (?, ?, ?)
`);

/* =========================
   UPLOAD STORAGE
========================= */

const storage = multer.diskStorage({
    destination: (_req, _file, cb) => {
        cb(null, TEMP_DIR);
    },

    filename: (_req, file, cb) => {
        const name =
            Date.now() +
            "-" +
            crypto.randomBytes(8).toString("hex") +
            ".zip";

        cb(null, name);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: MAX_ZIP_SIZE,
        files: MAX_BATCH_FILES
    }
});

/* =========================
   HELPERS
========================= */

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
                autoClose: true,
                validateEntrySizes: true
            },
            (err, zip) => {
                if (err) {
                    reject(err);
                } else {
                    resolve(zip);
                }
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

            stream.on("data", chunk => {
                size += chunk.length;

                if (size > MAX_SINGLE_FILE) {
                    stream.destroy(
                        new Error(
                            "File exceeds 60 MB limit."
                        )
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

function safeName(input, used) {
    let name = path.posix.basename(
        String(input).replace(/\\/g, "/")
    );

    name = name
        .replace(/[^a-zA-Z0-9._() -]/g, "_")
        .replace(/^[ .]+|[ .]+$/g, "");

    if (!name) name = "file";

    const ext = path.extname(name);
    const stem = path.basename(name, ext);

    let candidate = name;
    let number = 2;

    while (used.has(candidate.toLowerCase())) {
        candidate = `${stem}_${number++}${ext}`;
    }

    used.add(candidate.toLowerCase());

    return candidate;
}

function makeZip(files) {
    return new Promise((resolve, reject) => {
        const chunks = [];

        const archive = archiver("zip", {
            zlib: { level: 3 }
        });

        archive.on("data", chunk => {
            chunks.push(chunk);
        });

        archive.on("warning", err => {
            if (err.code !== "ENOENT") {
                reject(err);
            }
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

function safeBase(name) {
    return path
        .basename(name, path.extname(name))
        .replace(/[^a-zA-Z0-9_-]/g, "_")
        .slice(0, 50) || "archive";
}

function cleanFiles(files = []) {
    for (const file of files) {
        try {
            if (file && file.path) {
                fs.unlinkSync(file.path);
            }
        } catch (_) {}
    }
}

/* =========================
   REQUEST QUEUE
========================= */

let processingQueue = Promise.resolve();

function inQueue(task) {
    const result = processingQueue.then(task, task);

    processingQueue = result.catch(() => {});

    return result;
}

/* =========================
   ZIP PROCESSING
========================= */

async function processZip(buffer) {
    const zip = await openZip(buffer);

    const outputFiles = [];
    const newHashes = [];

    const localHashes = new Set();
    const usedNames = new Set();

    let totalFiles = 0;
    let duplicatesRemoved = 0;
    let ignoredFiles = 0;
    let expandedSize = 0;
    let entriesCount = 0;

    await new Promise((resolve, reject) => {
        let finished = false;

        function fail(err) {
            if (finished) return;

            finished = true;

            try {
                zip.close();
            } catch (_) {}

            reject(err);
        }

        zip.on("error", fail);

        zip.on("end", () => {
            if (!finished) {
                finished = true;
                resolve();
            }
        });

        zip.on("entry", async entry => {
            if (finished) return;

            try {
                if (++entriesCount > MAX_ENTRIES) {
                    throw new Error(
                        "ZIP contains more than 5000 entries."
                    );
                }

                if (/\/$/.test(entry.fileName)) {
                    zip.readEntry();
                    return;
                }

                const extension = path.extname(
                    entry.fileName
                ).toLowerCase();

                const allowed = [
                    ".pdf",
                    ".jpg",
                    ".jpeg"
                ];

                if (!allowed.includes(extension)) {
                    ignoredFiles++;
                    zip.readEntry();
                    return;
                }

                totalFiles++;

                if (
                    entry.uncompressedSize >
                    MAX_SINGLE_FILE
                ) {
                    ignoredFiles++;
                    zip.readEntry();
                    return;
                }

                expandedSize += entry.uncompressedSize;

                if (expandedSize > MAX_EXPANDED_SIZE) {
                    throw new Error(
                        "ZIP expanded size exceeds 300 MB."
                    );
                }

                const data = await readEntry(zip, entry);

                const hash = sha256(data);

                /*
                 Check old permanent database.
                 */

                const alreadyStored = hashExists.get(hash);

                /*
                 Also check duplicates inside
                 current ZIP.
                 */

                if (
                    alreadyStored ||
                    localHashes.has(hash)
                ) {
                    duplicatesRemoved++;
                } else {
                    localHashes.add(hash);

                    newHashes.push({
                        hash,
                        filename: entry.fileName
                    });

                    outputFiles.push({
                        name: safeName(
                            entry.fileName,
                            usedNames
                        ),
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

    /*
     Create output ZIP before saving fingerprints.
    */

    const outputBuffer = outputFiles.length
        ? await makeZip(outputFiles)
        : null;

    /*
     Save new fingerprints in the EXISTING
     file_fingerprints table.
    */

    const now = new Date().toISOString();

    db.transaction(items => {
        for (const item of items) {
            insertHash.run(
                item.hash,
                item.filename,
                now
            );
        }
    })(newHashes);

    return {
        outputBuffer,

        stats: {
            totalFiles,
            duplicatesRemoved,
            newUniqueFiles: outputFiles.length,
            ignoredFiles
        }
    };
}

/* =========================
   HEALTH CHECK
========================= */

app.get("/health", (_req, res) => {
    res.json({
        status: "ok",
        service: "ZIP Duplicate Checker"
    });
});

/* =========================
   DATABASE STATUS
========================= */

app.get("/api/status", (_req, res) => {
    try {
        const count = db.prepare(`
            SELECT COUNT(*) AS count
            FROM file_fingerprints
        `).get().count;

        res.json({
            storedUniqueFiles: count
        });

    } catch (err) {
        console.error("Database status error:", err);

        res.status(500).json({
            error: "Database status unavailable."
        });
    }
});

/* =========================
   SINGLE ZIP PROCESSING
========================= */

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
            cleanFiles([req.file]);

            return res.status(400).json({
                error: "Only ZIP files are supported."
            });
        }

        try {
            const result = await inQueue(async () => {
                const buffer = fs.readFileSync(
                    req.file.path
                );

                return processZip(buffer);
            });

            if (!result.outputBuffer) {
                return res.json({
                    message: "No new unique files found.",
                    stats: result.stats
                });
            }

            res.setHeader(
                "Content-Type",
                "application/zip"
            );

            res.setHeader(
                "Content-Disposition",
                `attachment; filename="unique_${safeBase(req.file.originalname)}.zip"`
            );

            res.setHeader(
                "X-Filter-Stats",
                Buffer.from(
                    JSON.stringify(result.stats)
                ).toString("base64")
            );

            return res.send(result.outputBuffer);

        } catch (err) {
            console.error("Single ZIP error:", err);

            return res.status(400).json({
                error: err.message ||
                    "Could not process ZIP."
            });

        } finally {
            cleanFiles([req.file]);
        }
    }
);

/* =========================
   BULK ZIP PROCESSING
========================= */

app.post(
    "/api/bulk-process",
    upload.array("zipfiles", MAX_BATCH_FILES),

    async (req, res) => {
        const files = req.files || [];

        if (!files.length) {
            return res.status(400).json({
                error: "Select at least one ZIP file."
            });
        }

        const totalBytes = files.reduce(
            (sum, file) => sum + file.size,
            0
        );

        if (
            files.some(file =>
                !file.originalname
                    .toLowerCase()
                    .endsWith(".zip")
            )
        ) {
            cleanFiles(files);

            return res.status(400).json({
                error: "Only ZIP files are supported."
            });
        }

        if (totalBytes > MAX_BATCH_SIZE) {
            cleanFiles(files);

            return res.status(413).json({
                error: "Total upload size exceeds 200 MB."
            });
        }

        const resultPath = path.join(
            TEMP_DIR,
            `bulk-${Date.now()}-${crypto.randomBytes(5).toString("hex")}.zip`
        );

        try {
            const totals = await inQueue(async () => {
                const summary = {
                    zipCount: files.length,
                    totalFiles: 0,
                    duplicatesRemoved: 0,
                    newUniqueFiles: 0,
                    ignoredFiles: 0,
                    perZip: []
                };

                const archive = archiver("zip", {
                    zlib: { level: 1 }
                });

                const output = fs.createWriteStream(
                    resultPath
                );

                const completed = new Promise(
                    (resolve, reject) => {
                        output.on("close", resolve);
                        output.on("error", reject);

                        archive.on("error", reject);

                        archive.on("warning", err => {
                            if (err.code !== "ENOENT") {
                                reject(err);
                            }
                        });
                    }
                );

                archive.pipe(output);

                /*
                 Process ZIPs sequentially.
                 Earlier ZIP fingerprints are saved
                 before the next ZIP is processed.
                */

                for (let i = 0; i < files.length; i++) {
                    const file = files[i];

                    const buffer = fs.readFileSync(
                        file.path
                    );

                    const processed = await processZip(
                        buffer
                    );

                    const stats = {
                        zipName: file.originalname,
                        ...processed.stats
                    };

                    summary.perZip.push(stats);

                    summary.totalFiles +=
                        stats.totalFiles;

                    summary.duplicatesRemoved +=
                        stats.duplicatesRemoved;

                    summary.newUniqueFiles +=
                        stats.newUniqueFiles;

                    summary.ignoredFiles +=
                        stats.ignoredFiles;

                    if (processed.outputBuffer) {
                        archive.append(
                            processed.outputBuffer,
                            {
                                name:
                                    `ZIP_${String(i + 1).padStart(2, "0")}_${safeBase(file.originalname)}_unique_files.zip`
                            }
                        );
                    }
                }

                archive.append(
                    Buffer.from(
                        JSON.stringify(summary, null, 2)
                    ),
                    {
                        name: "BULK_SUMMARY.json"
                    }
                );

                await archive.finalize();
                await completed;

                return summary;
            });

            res.setHeader(
                "Content-Type",
                "application/zip"
            );

            res.setHeader(
                "Content-Disposition",
                'attachment; filename="BULK_RESULT.zip"'
            );

            res.setHeader(
                "X-Bulk-Stats",
                Buffer.from(
                    JSON.stringify(totals)
                ).toString("base64")
            );

            const stream = fs.createReadStream(resultPath);

            stream.on("error", err => {
                console.error("Download error:", err);
                res.destroy(err);
            });

            stream.on("close", () => {
                try {
                    fs.unlinkSync(resultPath);
                } catch (_) {}
            });

            stream.pipe(res);

        } catch (err) {
            console.error("Bulk processing error:", err);

            try {
                fs.unlinkSync(resultPath);
            } catch (_) {}

            if (!res.headersSent) {
                res.status(400).json({
                    error: err.message ||
                        "Bulk processing failed."
                });
            }

        } finally {
            cleanFiles(files);
        }
    }
);

/* =========================
   MULTER ERROR HANDLER
========================= */

app.use((err, _req, res, _next) => {
    if (err instanceof multer.MulterError) {
        let message = err.message;
        let status = 400;

        if (err.code === "LIMIT_FILE_SIZE") {
            message = "Each ZIP maximum size is 100 MB.";
            status = 413;
        }

        if (err.code === "LIMIT_FILE_COUNT") {
            message = "Maximum 20 ZIP files allowed.";
            status = 413;
        }

        return res.status(status).json({
            error: message
        });
    }

    console.error("Server error:", err);

    res.status(500).json({
        error: "Internal server error."
    });
});

/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {
    console.log("--------------------------------");
    console.log("ZIP DUPLICATE CHECKER STARTED");
    console.log("Port:", PORT);
    console.log("Database:", DB_PATH);
    console.log("Database table: file_fingerprints");
    console.log("Maximum ZIP size: 100 MB");
    console.log("Maximum bulk size: 200 MB");
    console.log("Maximum ZIP count: 20");
    console.log("--------------------------------");

    const count = db.prepare(`
        SELECT COUNT(*) AS count
        FROM file_fingerprints
    `).get().count;

    console.log(
        "DATABASE TOTAL:",
        count
    );
});

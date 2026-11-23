/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.io

import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.util.zip.ZipEntry
import java.util.zip.ZipFile

/**
 * Hard memory and archive-expansion limits enforced while reading release binaries and archives
 * so malformed or malicious ZIP bombs cannot trigger out-of-memory errors.
 */
public data class BinaryReadLimits(
    public val maxSingleFileBytes: Long = DEFAULT_MAX_FILE_BYTES,
    public val maxZipEntryBytes: Long = DEFAULT_MAX_ZIP_ENTRY_BYTES,
    public val maxTotalZipBytes: Long = DEFAULT_MAX_TOTAL_ZIP_BYTES,
    public val maxZipEntries: Int = DEFAULT_MAX_ZIP_ENTRIES,
) {
    public companion object {
        /** Default 128 MiB cap for a single binary file (for example a Mach-O or WASM module). */
        public const val DEFAULT_MAX_FILE_BYTES: Long = 128L * 1024L * 1024L

        /** Default 64 MiB cap for a single decompressed ZIP entry (for example a DEX or `.so`). */
        public const val DEFAULT_MAX_ZIP_ENTRY_BYTES: Long = 64L * 1024L * 1024L

        /** Default 512 MiB cap for total decompressed bytes read from one archive. */
        public const val DEFAULT_MAX_TOTAL_ZIP_BYTES: Long = 512L * 1024L * 1024L

        /** Default maximum number of entries inspected inside a single archive. */
        public const val DEFAULT_MAX_ZIP_ENTRIES: Int = 50_000
    }
}

/** Tracks cumulative entry count and decompressed byte usage while scanning a ZIP archive. */
public class ZipReadBudget(
    private val limits: BinaryReadLimits = BinaryReadLimits(),
) {
    private var entriesSeen: Int = 0
    private var bytesRead: Long = 0L

    /** Records one archive entry and fails if [BinaryReadLimits.maxZipEntries] is exceeded. */
    public fun recordEntry(entryName: String) {
        entriesSeen += 1
        require(entriesSeen <= limits.maxZipEntries) {
            "Archive exceeded maximum entry limit (${limits.maxZipEntries}) at '$entryName'."
        }
    }

    /** Reads [entry] from [zip] while enforcing both per-entry and total-archive byte limits. */
    public fun readEntryBytes(
        zip: ZipFile,
        entry: ZipEntry,
        maxEntryBytes: Long = limits.maxZipEntryBytes,
    ): ByteArray {
        val remaining = (limits.maxTotalZipBytes - bytesRead).coerceAtLeast(0L)
        val cap = minOf(maxEntryBytes, remaining)
        require(entry.size < 0L || entry.size <= cap) {
            "ZIP entry '${entry.name}' (${entry.size} B) exceeds read budget ($cap B)."
        }
        val bytes = zip.getInputStream(entry).use { input ->
            BoundedBinaryIo.readStreamBounded(input, cap, "ZIP entry '${entry.name}'")
        }
        bytesRead += bytes.size.toLong()
        return bytes
    }
}

/** Bounded file, stream, and ZIP reading utilities protecting binary parsers against DoS/OOM. */
public object BoundedBinaryIo {
    private const val BUFFER_SIZE = 16 * 1024

    /** Reads [file] into memory if its length does not exceed [maxBytes]. */
    public fun readFileBounded(
        file: File,
        maxBytes: Long = BinaryReadLimits.DEFAULT_MAX_FILE_BYTES,
    ): ByteArray {
        val length = file.length()
        require(length <= maxBytes) {
            "File '${file.name}' ($length B) exceeds maximum readable limit ($maxBytes B)."
        }
        return file.inputStream().use { input ->
            readStreamBounded(input, maxBytes, "file '${file.name}'")
        }
    }

    /** Reads up to the first [maxBytes] bytes of [file] without loading the rest of the file into memory. */
    public fun readFilePrefix(file: File, maxBytes: Int): ByteArray {
        val target = if (maxBytes > 0 && file.isFile) {
            minOf(maxBytes.toLong(), file.length()).toInt().coerceAtLeast(0)
        } else {
            0
        }
        if (target == 0) return ByteArray(0)
        val buf = ByteArray(target)
        var offset = 0
        file.inputStream().use { input ->
            while (offset < target) {
                val read = input.read(buf, offset, target - offset)
                if (read <= 0) break
                offset += read
            }
        }
        return if (offset == buf.size) buf else buf.copyOf(offset)
    }

    /** Reads UTF-8 text from [file] if its byte length does not exceed [maxBytes]. */
    public fun readTextBounded(
        file: File,
        maxBytes: Long = BinaryReadLimits.DEFAULT_MAX_ZIP_ENTRY_BYTES,
    ): String = String(readFileBounded(file, maxBytes), Charsets.UTF_8)

    /** Reads at most [maxBytes] from [input], failing if additional data remains. */
    public fun readStreamBounded(
        input: InputStream,
        maxBytes: Long,
        label: String,
    ): ByteArray {
        val out = ByteArrayOutputStream()
        val buffer = ByteArray(BUFFER_SIZE)
        var total = 0L
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            total += read.toLong()
            require(total <= maxBytes) {
                "Reading $label exceeded maximum limit of $maxBytes bytes (possible archive bomb)."
            }
            out.write(buffer, 0, read)
        }
        return out.toByteArray()
    }
}

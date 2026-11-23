/*
 * SPDX-FileCopyrightText: 2023-2026 Ron June Valdoz
 *
 * SPDX-License-Identifier: Apache-2.0
 */
package com.awakekt.releaseguard.analyzers

import java.util.Locale

/**
 * Pure-Kotlin Protobuf wire-format decoder for Android App Bundle (`.aab`) `base/manifest/AndroidManifest.xml`
 * emitted by `aapt2 --proto-format`.
 */
internal object ProtobufManifestParser {
    private class ProtoAttrBuilder {
        var name: String = ""
        var rawValue: String? = null
        var resId: Int = 0
        var boolVal: Boolean? = null
        var intVal: Int? = null

        fun build(): ManifestParsedAttr = ManifestParsedAttr(
            name = name,
            resourceId = resId,
            stringValue = rawValue,
            boolValue = boolVal ?: rawValue?.lowercase(Locale.ROOT)?.toBooleanStrictOrNull(),
            intValue = intVal ?: rawValue?.toIntOrNull(),
        )
    }

    fun parse(bytes: ByteArray): AndroidManifestFlags {
        val acc = ManifestFlagsAccumulator()
        parseNode(bytes, 0, bytes.size, acc, 0)
        return acc.build()
    }

    private fun parseNode(bytes: ByteArray, start: Int, end: Int, acc: ManifestFlagsAccumulator, depth: Int) {
        if (depth > 32) return
        forEachField(bytes, start, end) { fieldNum, wireType, bodyStart, bodyEnd, _ ->
            if (fieldNum == 1 && wireType == 2) {
                parseElement(bytes, bodyStart, bodyEnd, acc, depth + 1)
            }
        }
    }

    private fun parseElement(bytes: ByteArray, start: Int, end: Int, acc: ManifestFlagsAccumulator, depth: Int) {
        var elementName = ""
        val attrs = mutableListOf<ManifestParsedAttr>()
        val children = mutableListOf<Pair<Int, Int>>()
        forEachField(bytes, start, end) { fieldNum, wireType, bodyStart, bodyEnd, _ ->
            if (wireType == 2) {
                when (fieldNum) {
                    2 -> elementName = String(bytes, bodyStart, (bodyEnd - bodyStart).coerceAtLeast(0), Charsets.UTF_8)
                    3 -> attrs += parseAttr(bytes, bodyStart, bodyEnd)
                    4 -> children += bodyStart to bodyEnd
                }
            }
        }
        if (elementName.isNotEmpty()) acc.recordElement(elementName, attrs)
        children.forEach { (cStart, cEnd) -> parseNode(bytes, cStart, cEnd, acc, depth + 1) }
        if (elementName in ManifestFlagsAccumulator.COMPONENT_TAGS) acc.finishComponent()
    }

    private fun parseAttr(bytes: ByteArray, start: Int, end: Int): ManifestParsedAttr {
        val builder = ProtoAttrBuilder()
        forEachField(bytes, start, end) { fieldNum, wireType, bodyStart, bodyEnd, varintVal ->
            when {
                wireType == 2 && fieldNum == 2 -> builder.name = String(bytes, bodyStart, (bodyEnd - bodyStart).coerceAtLeast(0), Charsets.UTF_8)
                wireType == 2 && fieldNum == 3 -> builder.rawValue = String(bytes, bodyStart, (bodyEnd - bodyStart).coerceAtLeast(0), Charsets.UTF_8)
                wireType == 2 && fieldNum == 5 -> applyCompiledItem(bytes, bodyStart, bodyEnd, builder)
                wireType == 0 && fieldNum == 4 -> builder.resId = varintVal.toInt()
            }
        }
        return builder.build()
    }

    private fun applyCompiledItem(bytes: ByteArray, start: Int, end: Int, builder: ProtoAttrBuilder) {
        forEachField(bytes, start, end) { fieldNum, wireType, bodyStart, bodyEnd, _ ->
            if (fieldNum == 4 && wireType == 2) {
                applyPrimitive(bytes, bodyStart, bodyEnd, builder)
            }
        }
    }

    private fun applyPrimitive(bytes: ByteArray, start: Int, end: Int, builder: ProtoAttrBuilder) {
        forEachField(bytes, start, end) { fieldNum, wireType, _, _, varintVal ->
            if (wireType == 0) {
                when (fieldNum) {
                    12 -> builder.boolVal = varintVal != 0L
                    5, 6 -> builder.intVal = varintVal.toInt()
                }
            }
        }
    }

    private inline fun forEachField(
        bytes: ByteArray,
        start: Int,
        end: Int,
        onField: (fieldNum: Int, wireType: Int, bodyStart: Int, bodyEnd: Int, varintVal: Long) -> Unit,
    ) {
        var pos = start
        while (pos < end) {
            val tagPair = readVarint(bytes, pos, end)
            if (tagPair == null) {
                pos = end
            } else {
                val (tag, next) = tagPair
                val fieldNum = (tag ushr 3).toInt()
                val wireType = (tag and 0x7L).toInt()
                pos = advanceAndDispatch(bytes, next, end, fieldNum, wireType, onField)
            }
        }
    }

    private inline fun advanceAndDispatch(
        bytes: ByteArray,
        next: Int,
        end: Int,
        fieldNum: Int,
        wireType: Int,
        onField: (Int, Int, Int, Int, Long) -> Unit,
    ): Int = when (wireType) {
        0 -> {
            val pair = readVarint(bytes, next, end)
            if (pair == null) end else { onField(fieldNum, wireType, next, pair.second, pair.first); pair.second }
        }
        1 -> (next + 8).coerceAtMost(end)
        2 -> {
            val pair = readVarint(bytes, next, end)
            if (pair == null) {
                end
            } else {
                val bodyStart = pair.second
                val bodyEnd = (bodyStart + pair.first.toInt()).coerceAtMost(end)
                onField(fieldNum, wireType, bodyStart, bodyEnd, 0L)
                bodyEnd
            }
        }
        5 -> (next + 4).coerceAtMost(end)
        else -> end
    }

    private fun readVarint(bytes: ByteArray, start: Int, end: Int): Pair<Long, Int>? {
        var pos = start
        var result = 0L
        var shift = 0
        while (pos < end && shift <= 63) {
            val b = bytes[pos].toLong() and 0xFFL
            pos += 1
            result = result or ((b and 0x7FL) shl shift)
            if ((b and 0x80L) == 0L) return result to pos
            shift += 7
        }
        return null
    }
}

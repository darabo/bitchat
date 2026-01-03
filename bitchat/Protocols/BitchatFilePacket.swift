//
// BitchatFilePacket.swift
// bitchat
//
// This is free and unencumbered software released into the public domain.
// For more information, see <https://unlicense.org>
//

import Foundation
import BitLogger
import CryptoKit

/// TLV payload for Bluetooth mesh file transfers (voice notes, images, generic files).
/// Mirrors the Android client specification to ensure cross-platform interoperability.
struct BitchatFilePacket {
    var fileName: String?
    var fileSize: UInt64?
    var mimeType: String?
    var content: Data
    var sha256: String?  // Computed SHA256 hash for integrity verification

    /// Canonical TLV tags defined by the Android implementation.
    private enum TLVType: UInt8 {
        case fileName = 0x01
        case fileSize = 0x02
        case mimeType = 0x03
        case content = 0x04
        case sha256 = 0x05  // Optional integrity verification
    }

    /// Encodes the packet using v2 canonical TLVs (4-byte FILE_SIZE, 4-byte CONTENT length).
    /// Returns `nil` when fields exceed protocol limits (e.g., content > UInt32.max).
    func encode() -> Data? {
        let resolvedSize = fileSize ?? UInt64(content.count)
        guard resolvedSize <= UInt64(UInt32.max) else { return nil }
        guard resolvedSize <= UInt64(FileTransferLimits.maxPayloadBytes) else { return nil }
        guard content.count <= Int(UInt32.max) else { return nil }
        guard FileTransferLimits.isValidPayload(content.count) else { return nil }

        func appendBE<T: FixedWidthInteger>(_ value: T, into data: inout Data) {
            var big = value.bigEndian
            withUnsafeBytes(of: &big) { data.append(contentsOf: $0) }
        }

        var encoded = Data()

        if let name = fileName, let nameData = name.data(using: .utf8), nameData.count <= Int(UInt16.max) {
            encoded.append(TLVType.fileName.rawValue)
            appendBE(UInt16(nameData.count), into: &encoded)
            encoded.append(nameData)
        }

        encoded.append(TLVType.fileSize.rawValue)
        appendBE(UInt16(4), into: &encoded)
        appendBE(UInt32(resolvedSize), into: &encoded)

        if let mime = mimeType, let mimeData = mime.data(using: .utf8), mimeData.count <= Int(UInt16.max) {
            encoded.append(TLVType.mimeType.rawValue)
            appendBE(UInt16(mimeData.count), into: &encoded)
            encoded.append(mimeData)
        }

        encoded.append(TLVType.content.rawValue)
        appendBE(UInt32(content.count), into: &encoded)
        encoded.append(content)
        
        // SHA256
        let digest = SHA256.hash(data: content)
        let sha256Data = Data(digest)
        encoded.append(TLVType.sha256.rawValue)
        appendBE(UInt16(sha256Data.count), into: &encoded)
        encoded.append(sha256Data)

        return encoded
    }

    /// Decodes TLV payloads, tolerating legacy encodings (FILE_SIZE len=8, CONTENT len=2) when possible.
    static func decode(_ data: Data) -> BitchatFilePacket? {
        var cursor = data.startIndex
        let end = data.endIndex

        var fileName: String?
        var fileSize: UInt64?
        var mimeType: String?
        var content = Data()
        var providedHash: String?

        while cursor < end {
            let typeRaw = data[cursor]
            cursor = data.index(after: cursor)

            guard cursor <= end else { return nil }
            let tlvType = TLVType(rawValue: typeRaw)

            func readBigEndianLength(bytes: Int) -> Int? {
                guard data.distance(from: cursor, to: end) >= bytes else { return nil }
                // Use UInt64 to prevent integer overflow during shift operations
                var result: UInt64 = 0
                for _ in 0..<bytes {
                    result = (result << 8) | UInt64(data[cursor])
                    cursor = data.index(after: cursor)
                }
                // Safely convert to Int with overflow check
                guard result <= Int.max else { return nil }
                return Int(result)
            }

            let length: Int?
            if tlvType == .content {
                let snapshot = cursor
                let canonical = readBigEndianLength(bytes: 4)
                if let canonical = canonical,
                   canonical <= data.distance(from: cursor, to: end) {
                    length = canonical
                } else {
                    cursor = snapshot
                    length = readBigEndianLength(bytes: 2)
                }
            } else {
                length = readBigEndianLength(bytes: 2)
            }

            guard let tlvLength = length, tlvLength >= 0 else { return nil }
            guard data.distance(from: cursor, to: end) >= tlvLength else { return nil }

            let valueStart = cursor
            cursor = data.index(cursor, offsetBy: tlvLength)
            let value = data[valueStart..<cursor]

            switch tlvType {
            case .fileName:
                fileName = String(data: Data(value), encoding: .utf8)
            case .fileSize:
                if tlvLength == 4 || tlvLength == 8 {
                    var size: UInt64 = 0
                    for byte in value {
                        size = (size << 8) | UInt64(byte)
                    }
                    if size > UInt64(FileTransferLimits.maxPayloadBytes) {
                        return nil
                    }
                    fileSize = size
                }
            case .mimeType:
                mimeType = String(data: Data(value), encoding: .utf8)
            case .content:
                let proposedSize = content.count + value.count
                if proposedSize > FileTransferLimits.maxPayloadBytes {
                    return nil
                }
                content.append(contentsOf: value)
            case .sha256:
                providedHash = value.compactMap { String(format: "%02x", $0) }.joined()
                continue
            case nil:
                continue
            }
        }

        guard !content.isEmpty else { return nil }
        guard FileTransferLimits.isValidPayload(content.count) else { return nil }
        
        // Compute SHA256 of received content for integrity verification
        let computedHash = SHA256.hash(data: content).compactMap { String(format: "%02x", $0) }.joined()
        
        // Verify integrity if provided
        if let provided = providedHash, provided != computedHash {
            SecureLogger.error("❌ Integrity check failed! Expected=\(provided), Computed=\(computedHash)", category: .session)
            return nil
        }
        
        return BitchatFilePacket(
            fileName: fileName,
            fileSize: fileSize ?? UInt64(content.count),
            mimeType: mimeType,
            content: content,
            sha256: computedHash
        )
    }
}

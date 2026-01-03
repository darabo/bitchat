import Foundation
import CryptoKit

/// Utility for symmetric encryption using AES-GCM.
class EncryptionUtils {
    
    struct EncryptedResult {
        let data: Data
        let key: Data
        let iv: Data
    }
    
    /// Encrypts data using AES-GCM with a randomly generated key
    static func encrypt(_ data: Data) throws -> EncryptedResult {
        // Generate random 32-byte key
        let key = SymmetricKey(size: .bits256)
        
        // Encrypt (CryptoKit handles IV/Nonce generation automatically if not specified, 
        // but we need to extract it to share it. 
        // AES.GCM.seal(data, using: key) generates a sealed box with nonce/tag/ciphertext.
        
        let sealedBox = try AES.GCM.seal(data, using: key)
        
        // sealedBox.combined provides everything, but we want to split it:
        // We want key (separate), nonce (separate), ciphertext+tag (uploaded).
        // NIP-44 style or just simple key+iv sharing?
        // Android side implemented: Cipher(AES/GCM/NoPadding).
        // This usually produces Ciphertext || Tag.
        // Android used a specific IV.
        
        // For compatibility with the simple "decryptionKey=hex&iv=hex" scheme I designed:
        // The URL anchor has key and IV.
        // The file content is Ciphertext + Tag.
        // CryptoKit's `sealedBox.ciphertext` includes the tag usually? 
        // No, `sealedBox.ciphertext` is just ciphertext. `sealedBox.tag` is separate.
        // `sealedBox.combined` is Nonce || Ciphertext || Tag.
        
        // Android implementation: `cipher.doFinal(data)`. 
        // Bouncy Castle/Android GCM `doFinal` usually appends the authentication tag to the ciphertext.
        // It does NOT include the IV.
        
        // So on iOS, to match Android's `doFinal` output (Ciphertext + Tag):
        // We need `sealedBox.ciphertext + sealedBox.tag`.
        
        let ciphertextWithTag = sealedBox.ciphertext + sealedBox.tag
        
        // Extract key data
        let keyData = key.withUnsafeBytes { Data($0) }
        
        // Extract nonce (IV)
        let ivData = Data(sealedBox.nonce)
        
        return EncryptedResult(data: ciphertextWithTag, key: keyData, iv: ivData)
    }
    
    static func hexString(from data: Data) -> String {
        return data.map { String(format: "%02x", $0) }.joined()
    }
}

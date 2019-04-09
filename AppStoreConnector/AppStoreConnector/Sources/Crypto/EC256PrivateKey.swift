import Foundation
import CommonCrypto
import Security

/// An elliptic curve private key
public struct EC256PrivateKey {
    
    fileprivate enum Errors: Error {
        case dataIsNotBase64Encoded
        case privateKeyConversionFailed
        case invalidASN1
        case invalidPrivateKey(underlyingError: Error)
        case signingFailed(underlyingError: CFError?)
        case verificationFailed(underlyingError: CFError?)
    }
    
    /// The key is guaranteed to be a 256-bit elliptic curve private key
    private let key: SecKey
    
    /// Creates a private key
    ///
    /// `pemFormatted` both with or with PEM header lines are supported
    ///
    /// - Parameter pemFormatted: A PEM formatted private key data.
    /// - Throws: If `pemFormatted` is not in the expected shape
    public init(pemFormatted: String) throws {
        do {
            key = try type(of: self).makeSecKey(from: pemFormatted)
        } catch {
            throw Errors.invalidPrivateKey(underlyingError: error)
        }
    }
    
    func sign(_ message: Data) throws -> ES256Signature {
        
        let digest = self.digest(for: message)
        
        var error: Unmanaged<CFError>?
        
        guard let signature = SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256, digest as CFData, &error) else {
            throw Errors.signingFailed(underlyingError: error?.takeRetainedValue())
        }
        
        return try (signature as Data).toRawSignature()
    }
    
    func verify(_ message: Data, hasSignature signature: ES256Signature) throws {
        
        let digest = self.digest(for: message)
        
        var error: Unmanaged<CFError>?
        
        let data = signature.data(using: .jws)
        let r = data[0..<32]
        let s = data[32..<64]
        
        // https://crypto.stackexchange.com/questions/57731/ecdsa-signature-rs-to-asn1-der-encoding-question
        
        let makeASN1Int = { (value: Data) -> Data in
            let hasLeadingZero = (value.first! & 0b1000_0000) == 0
            let header: Data
            if hasLeadingZero {
                header = Data([2, UInt8(value.count)])
            } else {
                header = Data([2, UInt8(value.count) + 1, 0])
            }
            return header + value
        }
        
        let integers = makeASN1Int(r) + makeASN1Int(s)
        let asn1 = Data([0x30, UInt8(integers.count)]) + integers

        guard
            let publicKey = SecKeyCopyPublicKey(key),
            SecKeyVerifySignature(publicKey, .ecdsaSignatureDigestX962SHA256, digest as CFData, asn1 as CFData, &error) else {
                throw Errors.verificationFailed(underlyingError: error?.takeRetainedValue())
        }
    }
    
}

private extension EC256PrivateKey {
    
    static func makeSecKey(from pemFormatted: String) throws -> SecKey {
        let undecoratedString = pemFormatted
            .split(separator: "\n")
            .filter { !($0.isEmpty || $0.hasPrefix("-----")) }
            .joined()
        guard let asn1 = Data(base64Encoded: undecoratedString) else {
            throw Errors.dataIsNotBase64Encoded
        }
        return try asn1.toECKeyData().toPrivateKey()
    }
    
    private func digest(for message: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256((message as NSData).bytes, CC_LONG(message.count), &hash)
        return Data(hash)
    }
    
}

// Source: [AppStoreConnect-Swift-SDK](https://github.com/AvdLee/appstoreconnect-swift-sdk)
// Created by Antoine van der Lee on 08/11/2018.

private extension Data {
    
    private indirect enum ASN1Element {
        case seq(elements: [ASN1Element])
        case integer(int: Int)
        case bytes(data: Data)
        case constructed(tag: Int, elem: ASN1Element)
        case unknown
    }
    
    func toECKeyData() throws -> Data {
        let (result, _) = toASN1Element()
        
        guard case let ASN1Element.seq(elements: es) = result,
            case let ASN1Element.bytes(data: privateOctest) = es[2] else {
                throw EC256PrivateKey.Errors.invalidASN1
        }
        
        let (octest, _) = privateOctest.toASN1Element()
        guard case let ASN1Element.seq(elements: seq) = octest,
            case let ASN1Element.bytes(data: privateKeyData) = seq[1],
            case let ASN1Element.constructed(tag: _, elem: publicElement) = seq[3],
            case let ASN1Element.bytes(data: publicKeyData) = publicElement else {
                throw EC256PrivateKey.Errors.invalidASN1
        }
        
        let keyData = (publicKeyData.drop(while: { $0 == 0x00}) + privateKeyData)
        return keyData
    }
    
    func toPrivateKey() throws -> SecKey {
        var error: Unmanaged<CFError>?
        
        guard let privateKey =
            SecKeyCreateWithData(self as CFData,
                                 [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                                  kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                                  kSecAttrKeySizeInBits: 256] as CFDictionary,
                                 &error) else {
                                    throw EC256PrivateKey.Errors.privateKeyConversionFailed
        }
        return privateKey
    }
    
    // SecKeyCreateSignature seems to sometimes return a leading zero; strip it out
    private func dropLeadingBytes() -> Data {
        if self.count == 33 {
            return self.dropFirst()
        }
        return self
    }
    
    /// Convert an ASN.1 format EC signature returned by commoncrypto into a raw 64bit signature
    func toRawSignature() throws -> ES256Signature {
        let (result, _) = self.toASN1Element()
        
        guard case let ASN1Element.seq(elements: es) = result,
            case let ASN1Element.bytes(data: sigR) = es[0],
            case let ASN1Element.bytes(data: sigS) = es[1] else {
                throw EC256PrivateKey.Errors.invalidASN1
        }
        
        let rawSig = sigR.dropLeadingBytes() + sigS.dropLeadingBytes()
        return try ES256Signature(data: rawSig, encoding: .jws)
    }
    
    private func readLength() -> (Int, Int) {
        if self[0] & 0x80 == 0x00 { // short form
            return (Int(self[0]), 1)
        } else {
            let lenghOfLength = Int(self[0] & 0x7F)
            var result: Int = 0
            for i in 1..<(1 + lenghOfLength) {
                result = 256 * result + Int(self[i])
            }
            return (result, 1 + lenghOfLength)
        }
    }
    
    private func toASN1Element() -> (ASN1Element, Int) {
        guard self.count >= 2 else {
            // format error
            return (.unknown, self.count)
        }
        
        switch self[0] {
        case 0x30: // sequence
            let (length, lengthOfLength) = self.advanced(by: 1).readLength()
            var result: [ASN1Element] = []
            var subdata = self.advanced(by: 1 + lengthOfLength)
            var alreadyRead = 0
            
            while alreadyRead < length {
                let (e, l) = subdata.toASN1Element()
                result.append(e)
                subdata = subdata.count > l ? subdata.advanced(by: l) : Data()
                alreadyRead += l
            }
            return (.seq(elements: result), 1 + lengthOfLength + length)
            
        case 0x02: // integer
            let (length, lengthOfLength) = self.advanced(by: 1).readLength()
            if length < 8 {
                var result: Int = 0
                let subdata = self.advanced(by: 1 + lengthOfLength)
                // ignore negative case
                for i in 0..<length {
                    result = 256 * result + Int(subdata[i])
                }
                return (.integer(int: result), 1 + lengthOfLength + length)
            }
            // number is too large to fit in Int; return the bytes
            return (.bytes(data: self.subdata(in: (1 + lengthOfLength) ..< (1 + lengthOfLength + length))), 1 + lengthOfLength + length)
            
        case let s where (s & 0xe0) == 0xa0: // constructed
            let tag = Int(s & 0x1f)
            let (length, lengthOfLength) = self.advanced(by: 1).readLength()
            let subdata = self.advanced(by: 1 + lengthOfLength)
            let (e, _) = subdata.toASN1Element()
            return (.constructed(tag: tag, elem: e), 1 + lengthOfLength + length)
            
        default: // octet string
            let (length, lengthOfLength) = self.advanced(by: 1).readLength()
            return (.bytes(data: self.subdata(in: (1 + lengthOfLength) ..< (1 + lengthOfLength + length))), 1 + lengthOfLength + length)
        }
    }
}

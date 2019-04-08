import Foundation

/// A Key for communicating with App Store Connect API
public struct APIKey {
    
    fileprivate enum Errors: Error {
        case dataIsNotBase64Encoded
        case privateKeyConversionFailed
        case invalidASN1
        case invalidPrivateKey(underlyingError: Error)
    }
    
    private let key: SecKey
    
    /// Creates an API Key
    ///
    /// `pemFormattedString` both with or with PEM header lines are supported
    ///
    /// - Parameter pemFormattedString: A PEM formatted private key data.
    /// - Throws: If the `pemFormattedString` is not in the expected shape for an App Store Connect key
    public init(pemFormattedString: String) throws {
        do {
            key = try type(of: self).makeSecKey(from: pemFormattedString)
        } catch {
            throw Errors.invalidPrivateKey(underlyingError: error)
        }
    }
    
}

private extension APIKey {
    
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
                throw APIKey.Errors.invalidASN1
        }
        
        let (octest, _) = privateOctest.toASN1Element()
        guard case let ASN1Element.seq(elements: seq) = octest,
            case let ASN1Element.bytes(data: privateKeyData) = seq[1],
            case let ASN1Element.constructed(tag: _, elem: publicElement) = seq[3],
            case let ASN1Element.bytes(data: publicKeyData) = publicElement else {
                throw APIKey.Errors.invalidASN1
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
                                    throw APIKey.Errors.privateKeyConversionFailed
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
    func toRawSignature() throws -> Data {
        let (result, _) = self.toASN1Element()
        
        guard case let ASN1Element.seq(elements: es) = result,
            case let ASN1Element.bytes(data: sigR) = es[0],
            case let ASN1Element.bytes(data: sigS) = es[1] else {
                throw APIKey.Errors.invalidASN1
        }
        
        let rawSig = sigR.dropLeadingBytes() + sigS.dropLeadingBytes()
        return rawSig
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

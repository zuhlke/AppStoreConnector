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
            let scalars = try EC256PrivateKeyScalars(pemFormatted: pemFormatted)
            key = try scalars.makePrivateKey()
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
        
        return try ES256Signature(data: signature as Data, encoding: .asn1)
    }
    
    func verify(_ message: Data, hasSignature signature: ES256Signature) throws {
        
        let digest = self.digest(for: message)
        let asn1 = signature.data(using: .asn1)
        
        var error: Unmanaged<CFError>?

        guard
            let publicKey = SecKeyCopyPublicKey(key),
            SecKeyVerifySignature(publicKey, .ecdsaSignatureDigestX962SHA256, digest as CFData, asn1 as CFData, &error) else {
                throw Errors.verificationFailed(underlyingError: error?.takeRetainedValue())
        }
    }
    
}

private extension EC256PrivateKey {
    
    private func digest(for message: Data) -> Data {
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256((message as NSData).bytes, CC_LONG(message.count), &hash)
        return Data(hash)
    }
    
}

private struct EC256PrivateKeyScalars {
    // All scalars are 32 bytes
    private var k: Data
    private var x: Data
    private var y: Data
    
    init(pemFormatted: String) throws {
        let undecoratedString = pemFormatted
            .split(separator: "\n")
            .filter { !($0.isEmpty || $0.hasPrefix("-----")) }
            .joined()
        guard let asn1 = Data(base64Encoded: undecoratedString) else {
            throw EC256PrivateKey.Errors.dataIsNotBase64Encoded
        }
        try self.init(asn1: asn1)
    }
    
    init(asn1: Data) throws {
        
        // Expecting PKCS#8 content
        // Spec: https://tools.ietf.org/html/rfc5208#appendix-A
        
        // PrivateKeyInfo ::= SEQUENCE {
        //     version Version,
        //     privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
        //     privateKey PrivateKey,
        //     attributes [0] Attributes OPTIONAL
        // }
        
        var scanner = ASN1Scanner(data: asn1)
        try scanner.scanSequenceHeader()
        
        // Version ::= INTEGER {v1(0)} (v1,...)
        let version = try scanner.scanInteger()
        guard version == Data([0]) else {
            throw EC256PrivateKey.Errors.invalidASN1
        }
        
        // AlgorithmIdentifier (https://tools.ietf.org/html/rfc5280#section-4.1.1.2)
        // AlgorithmIdentifier  ::=  SEQUENCE  {
        //     algorithm               OBJECT IDENTIFIER,
        //     parameters              ANY DEFINED BY algorithm OPTIONAL
        // }
        let algorithmIdentifierLength = try scanner.scanSequenceHeader()
        scanner.stream = scanner.stream.dropFirst(algorithmIdentifierLength)
        
        // PrivateKey octet data should contain an ECPrivateKey
        // spec: https://tools.ietf.org/html/rfc5915
        // ECPrivateKey ::= SEQUENCE {
        //     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
        //     privateKey     OCTET STRING,
        //     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,
        //     publicKey  [1] BIT STRING OPTIONAL
        // }
        let privateKeyData = try scanner.scanOctet()
        var privateKeyScanner = ASN1Scanner(data: privateKeyData)
        
        try privateKeyScanner.scanSequenceHeader()
        let ecVersion = try privateKeyScanner.scanInteger()
        guard ecVersion == Data([1]) else {
            throw EC256PrivateKey.Errors.invalidASN1
        }
        
        // privateKey
        k = try privateKeyScanner.scanOctet()
        
        // parameters
        try privateKeyScanner.scanTag(0)
        
        // public key
        try privateKeyScanner.scanTagHeader(1)
        let publicKey = try privateKeyScanner.scanBitString()
        let publicKeyIsUncompressed = publicKey.starts(with: [0x00, 0x04])
        guard publicKeyIsUncompressed else {
            throw EC256PrivateKey.Errors.invalidASN1
        }
        
        x = publicKey[publicKey.startIndex+2..<publicKey.startIndex+2+32]
        y = publicKey[publicKey.startIndex+2+32..<publicKey.startIndex+2+32+32]
    }
    
    func makePrivateKey() throws -> SecKey {
        // See `SecKeyCopyExternalRepresentation`
        let data = Data([4]) + x + y + k
        
        var error: Unmanaged<CFError>?
        guard let privateKey =
            SecKeyCreateWithData(data as CFData,
                                 [kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
                                  kSecAttrKeyClass: kSecAttrKeyClassPrivate,
                                  kSecAttrKeySizeInBits: 256] as CFDictionary,
                                 &error) else {
                                    throw EC256PrivateKey.Errors.privateKeyConversionFailed
        }
        return privateKey
    }
    
}

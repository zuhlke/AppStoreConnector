import Foundation

/// A signature made with ECDSA using P-256 and SHA-256.
struct ES256Signature {
    
    // `r` and `s` are both guaranteed to be 32 bytes
    fileprivate let r: Data
    fileprivate let s: Data
    
    private init(r: Data, s: Data) {
        precondition(r.count == 32)
        precondition(s.count == 32)
        self.r = r
        self.s = s
    }
    
}

extension ES256Signature {
    
    struct Encoding {
        fileprivate var encode: (ES256Signature) -> Data
        fileprivate var decode: (Data) throws -> ES256Signature
    }
    
    func data(using encoding: Encoding) -> Data {
        return encoding.encode(self)
    }
    
    init(data: Data, encoding: Encoding) throws {
        self = try encoding.decode(data)
    }
    
}

extension ES256Signature.Encoding {
    
    private enum Errors: Error {
        case invalidSignatureData
    }
    
    /// JWS encoding
    ///
    /// Spec: https://tools.ietf.org/html/rfc7518#section-3.4
    static let jws = ES256Signature.Encoding(
        encode: { $0.r + $0.s },
        decode: { data in
            guard data.count == 64 else {
                throw Errors.invalidSignatureData
            }
            let start = data.startIndex
            return ES256Signature(
                r: data[start..<start+32],
                s: data[start+32..<start+64]
            )
    }
    )
    
}

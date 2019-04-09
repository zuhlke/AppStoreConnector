import Foundation

struct ASN1Scanner {
    
    private enum Tag: UInt8 {
        case integer = 0x02
        case sequence = 0x30
    }
    
    private enum Errors: Error {
        case invalidStream
    }
    
    private var stream: Data
    
    init(data: Data) {
        self.stream = data
    }
    
    @discardableResult
    mutating func scanSequenceHeader() throws -> Int {
        return try scanLength(for: .sequence)
    }
    
    @discardableResult
    mutating func scanInteger() throws -> Data {
        let length = try scanLength(for: .integer)
        
        defer {
            stream = stream.dropFirst(length)
        }
        return stream.prefix(length)
    }
    
    @discardableResult
    private mutating func scanLength(for tag: Tag) throws -> Int {
        guard stream.popFirst() == tag.rawValue, !stream.isEmpty else {
            throw Errors.invalidStream
        }
        
        let length = Int(stream.popFirst()!)
        guard stream.count >= length else {
            throw Errors.invalidStream
        }
        
        return length
    }
    
}

import XCTest
import AppStoreConnector
import RxSwift
import RxCocoa
import RxBlocking

private struct Environment: Decodable {
    var keyId: String
    var issuerId: String
    var keyFilePath: String
    var logFilePath: String
}

private extension ProcessInfo {
    
    func decodeEnvironments<T: Decodable>(as type: T.Type) throws -> T {
        let data = try JSONEncoder().encode(environment)
        
        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        return try decoder.decode(type, from: data)
    }
    
}
private class IntegrationContext {
    
    let client: APIClient
    let misconfiguredClient: APIClient

    private let _log: (String) -> Void
    
    init() {
        let environment = try! ProcessInfo.processInfo.decodeEnvironments(as: Environment.self)
        
        let keyFile = URL(fileURLWithPath: environment.keyFilePath)
        let key = try! EC256PrivateKey(contentsOf: keyFile)
        
        client = APIClient(
            key: key,
            keyID: environment.keyId,
            issuerID: environment.issuerId
        )
        
        misconfiguredClient = APIClient(
            key: key,
            keyID: environment.keyId,
            issuerID: UUID().uuidString
        )
        
        var logBody = "\(Date())\n"
        
        _log = { message in
            logBody.append(contentsOf: message)
            logBody.append("\n")
            try! logBody.write(toFile: environment.logFilePath, atomically: true, encoding: .utf8)
        }
    }
    
    func log(_ message: String) {
        _log(message)
    }
    
    func log(_ data: Data) {
        log(String(data: data, encoding: .utf8)!)
    }
    
    func log<T>(_ value: T) {
        log("\(value)")
    }
    
}

class IntegrationTests: XCTestCase {
    
    private lazy var c = IntegrationContext()
    
    func testUsingMisconfiguredClientReturnsError() {
        let request = c.misconfiguredClient.request("/apps")
        do {
            _ = try request.toBlocking().single()
            XCTFail("Expected call to fail")
        } catch APIClient.Errors.httpError(let statusCode) {
            XCTAssertEqual(statusCode, 401)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
    func testHittingBasicAPI() throws {
        let response = try c.client.request("/apps")
            .toBlocking().single()
        c.log(response)
    }
    
}

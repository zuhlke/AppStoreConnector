import XCTest
@testable import AppStoreConnector
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
    
    let tokenGenerator: AuthTokenGenerator
    
    private let _log: (String) -> Void
    
    init() {
        let environment = try! ProcessInfo.processInfo.decodeEnvironments(as: Environment.self)
        
        let keyFile = URL(fileURLWithPath: environment.keyFilePath)
        let key = try! EC256PrivateKey(contentsOf: keyFile)
        
        tokenGenerator = AuthTokenGenerator(
            key: key,
            keyID: environment.keyId,
            issuerID: environment.issuerId
        )
        
        var logBody = ""
        
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
    
}

class IntegrationTests: XCTestCase {
    
    private let c = IntegrationContext()
    
    func testHittingBasicAPI() throws {
        let expiryDate = Date(timeIntervalSinceNow: 60)
        let token = try c.tokenGenerator.token(expiryingAt: expiryDate)
        let url = URL(string: "https://api.appstoreconnect.apple.com/v1/apps")!
        var request = URLRequest(url: url)
        request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        
        let response = try URLSession.shared.rx
            .data(request: request)
            .toBlocking().single()
        c.log(response)
    }
    
}
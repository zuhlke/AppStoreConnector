import XCTest
import RxSwift
@testable import AppStoreConnector

private struct MockRequestGenerator: RequestGenerator {
    var request: URLRequest
    func request(for path: String) -> URLRequest {
        return request
    }
}

private extension MockRequestGenerator {
    
    init() {
        let request = URLRequest(url: URL(string: "https://somewhere")!)
        self.init(request: request)
    }
    
}

private struct MockNetworkingDelegate: NetworkingDelegate {
    var response: HTTPURLResponse
    var data: Data
    
    func response(for request: URLRequest) -> Observable<(response: HTTPURLResponse, data: Data)> {
        return Observable.just((response, data))
    }
}

class ConnectionTests: XCTestCase {
    
    func testHTTPErrorsAreCaptured() throws {
        let generator = MockRequestGenerator()
        let networkingDelegate = MockNetworkingDelegate(
            response: HTTPURLResponse(
                url: generator.request.url!,
                statusCode: 403,
                httpVersion: nil,
                headerFields: nil
            )!,
            data: Data()
        )
        
        let connection = Connection(requestGenerator: generator, networkingDelegate: networkingDelegate)
        
        do {
            _ = try connection.request("").toBlocking().single()
            XCTFail("Expected call to fail")
        } catch Connection.Errors.httpError(let statusCode) {
            XCTAssertEqual(statusCode, 403)
        } catch {
            XCTFail("Unexpected error: \(error)")
        }
    }
    
}

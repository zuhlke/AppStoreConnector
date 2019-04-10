import Foundation
import RxSwift
import RxCocoa

public class APIClient {
    
    public enum Errors: Error {
        case httpError(statusCode: Int)
    }
    
    private let requestGenerator: AuthenticatedRequestGenerator
    
    public init(key: EC256PrivateKey, keyID: String, issuerID: String) {
        let tokenGenerator = AuthTokenGenerator(
            key: key,
            keyID: keyID,
            issuerID: issuerID
        )
        
        requestGenerator = AuthenticatedRequestGenerator(host: "api.appstoreconnect.apple.com", path: "/v1") {
            let expiryDate = Date(timeIntervalSinceNow: 60)
            return try! tokenGenerator.token(expiryingAt: expiryDate)
        }
        
        Logging.URLRequests = { _ in false }
    }
    
    public func request(_ path: String) -> Observable<Data> {
        let request = requestGenerator.request(for: path)
        return URLSession.shared.rx.response(request: request).map { (response, data) -> Data in
            switch response.statusCode {
            case 200..<300:
                return data
            default:
                throw Errors.httpError(statusCode: response.statusCode)
            }
        }
    }

}

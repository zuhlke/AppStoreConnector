import Foundation
import RxSwift
import RxCocoa

public class Connection {
    
    public enum Errors: Error {
        case httpError(statusCode: Int)
    }
    
    private let requestGenerator: RequestGenerator
    private let networkingDelegate: NetworkingDelegate
    
    init(requestGenerator: RequestGenerator, networkingDelegate: NetworkingDelegate) {
        self.networkingDelegate = networkingDelegate
        self.requestGenerator = requestGenerator
    }
    
    public func request(_ path: String) -> Observable<Data> {
        let request = requestGenerator.request(for: path)
        return networkingDelegate.response(for: request).map { (response, data) -> Data in
            switch response.statusCode {
            case 200..<300:
                return data
            default:
                throw Errors.httpError(statusCode: response.statusCode)
            }
        }
    }

}

public extension Connection {
    
    convenience init(key: EC256PrivateKey, keyID: String, issuerID: String, networkingDelegate: NetworkingDelegate = URLSession.shared.rx) {
        let tokenGenerator = AuthTokenGenerator(
            key: key,
            keyID: keyID,
            issuerID: issuerID
        )
        
        let requestGenerator = AuthenticatedRequestGenerator(host: "api.appstoreconnect.apple.com", path: "/v1") {
            let expiryDate = Date(timeIntervalSinceNow: 60)
            return try! tokenGenerator.token(expiryingAt: expiryDate)
        }
        
        self.init(requestGenerator: requestGenerator, networkingDelegate: networkingDelegate)
    }
    
}

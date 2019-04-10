import Foundation
import RxSwift
import RxCocoa

public class APIClient {
    
    private let tokenGenerator: AuthTokenGenerator
    
    private let baseURLComponents: URLComponents
    
    init(key: EC256PrivateKey, keyID: String, issuerID: String) {
        tokenGenerator = AuthTokenGenerator(
            key: key,
            keyID: keyID,
            issuerID: issuerID
        )
        
        baseURLComponents = mutating(URLComponents()) {
            $0.scheme = "https"
            $0.host = "api.appstoreconnect.apple.com"
            $0.path = "/v1"
        }
    }
    
    public func request(_ path: String) -> Observable<Data> {
        do {
            let expiryDate = Date(timeIntervalSinceNow: 60)
            let token = try tokenGenerator.token(expiryingAt: expiryDate)
            let urlComponents = mutating(baseURLComponents) {
                $0.path += path
            }
            
            var request = URLRequest(url: urlComponents.url!)
            request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
            
            return URLSession.shared.rx.data(request: request)
        } catch {
            return Observable.error(error)
        }
    }

}

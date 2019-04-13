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

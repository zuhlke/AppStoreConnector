import Foundation
import RxSwift
import RxCocoa

public protocol NetworkingDelegate {
    
    func response(for request: URLRequest) -> Observable<(response: HTTPURLResponse, data: Data)>
    
}

extension Reactive: NetworkingDelegate where Base: URLSession {
    
    public func response(for request: URLRequest) -> Observable<(response: HTTPURLResponse, data: Data)> {
        return self.response(request: request)
    }
    
}

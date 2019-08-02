import Foundation
import Combine

public protocol NetworkingDelegate {
    
    func response(for request: URLRequest) -> AnyPublisher<(response: HTTPURLResponse, data: Data), URLError>
        
}

extension URLSession: NetworkingDelegate {
    
    public func response(for request: URLRequest) -> AnyPublisher<(response: HTTPURLResponse, data: Data), URLError> {
        return self.dataTaskPublisher(for: request)
            .map { data, response in
                (response as! HTTPURLResponse, data)
            }.eraseToAnyPublisher()
    }
    
}

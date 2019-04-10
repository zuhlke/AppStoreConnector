import Foundation

protocol RequestGenerator {
    func request(for path: String) -> URLRequest
}

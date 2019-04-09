import XCTest
import AppStoreConnector

class APIKeyTests: XCTestCase {
    
    func testThatInitializerThrowsForInvalidPrivateKey() {
        XCTAssertThrowsError(try APIKey(pemFormatted: UUID().uuidString))
    }
    
    func testThatInitializerDoesNotThrowForValidPrivateKeyWithoutPEMDecoration() {
        XCTAssertNoThrow(try APIKey(pemFormatted: SampleKey.pemString))
    }
    
    func testThatInitializerDoesNotThrowForValidPrivateKeyWithPEMDecoration() {
        XCTAssertNoThrow(try APIKey(pemFormatted: SampleKey.pemStringWithDecodaration))
    }
    
}

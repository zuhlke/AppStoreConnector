import XCTest
import AppStoreConnector

private let validKey =
"MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgwseAmqhyAPMALO1rbCDVbhn0M9tWGBVYJdVVx/aczkegCgYIKoZIzj0DAQehRANCAAR7BPlyY9GOG7V+yQlz84sRm7WIN4JU5XhcvyiECctnLHaS9sUYc43dMeNZ0qDBY7LPFiLiHqm3eUZj4xuH97HJ"

private let validKeyWithPEMDecodaration =
"""
-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQgwseAmqhyAPMALO1r
bCDVbhn0M9tWGBVYJdVVx/aczkegCgYIKoZIzj0DAQehRANCAAR7BPlyY9GOG7V+
yQlz84sRm7WIN4JU5XhcvyiECctnLHaS9sUYc43dMeNZ0qDBY7LPFiLiHqm3eUZj
4xuH97HJ
-----END PRIVATE KEY-----
"""

class APIKeyTests: XCTestCase {
    
    func testThatInitializerThrowsForInvalidPrivateKey() {
        XCTAssertThrowsError(try APIKey(pemFormattedString: UUID().uuidString))
    }
    
    func testThatInitializerDoesNotThrowForValidPrivateKeyWithoutPEMDecoration() {
        XCTAssertNoThrow(try APIKey(pemFormattedString: validKey))
    }
    
    func testThatInitializerDoesNotThrowForValidPrivateKeyWithPEMDecoration() {
        XCTAssertNoThrow(try APIKey(pemFormattedString: validKeyWithPEMDecodaration))
    }
    
}

import Foundation
import BCFoundation

/// Function identifiers (`Function`) are used in the envelope to select which call
/// the receiver is to perform.
public extension Function {
    /// Here we are using a "named" function identifier, which is encoded directly in
    /// the envelope as a string. If space is a consideration, one could instead
    /// define a "known" identifier, which is encoded as a much shorter integer.
    static let coldCardSign = Function("coldCardSign")
}

/// Parameter identifiers (`Parameter`) are used in the envelope to designate each
/// argument passed to the function.
public extension Parameter {
    /// Like function identifiers, parameters can be designated by strings or integers.
    /// For simplicity in this example we're using strings.
    static let message = Parameter("message")
    static let path = Parameter("path")
}

/// This is the body of a request to sign a message in ColdCard-compliant format.
///
/// The `path` parameter is optional.
public struct ColdCardSignatureRequestBody {
    public let messageString: String
    public let path: DerivationPath?

    public var message: Data {
        messageString.utf8Data
    }

    public init(messageString: String, path: DerivationPath? = nil) {
        self.messageString = messageString
        self.path = path
    }
    
    public init(message: Data, path: DerivationPath? = nil) throws {
        /// Reject any passed-in message that is not valid UTF-8
        guard let messageString = message.utf8 else {
            throw ExampleSigner.Error.invalidMessage
        }
        self.init(messageString: messageString, path: path)
    }
}

/// This protocol collects the things that every request that can be made to the
/// signing service has in common. No matter how many different methods of signing
/// this service offers, there will always be a message to sign.
public protocol SignatureRequestBody: TransactionRequestBody {
    var message: Data { get }
}

/// This extension conforms `ColdCardRequestBody` to `SignatureRequestBody` and
/// `TransactionRequestBody` from which it inherits, by declaring its function
/// identifier and how to encode and decode the body as an envelope.
extension ColdCardSignatureRequestBody: SignatureRequestBody {
    public static var function: Function = .coldCardSign

    /// This method encodes the body structured as an envelope.
    ///
    /// For a function body, the subject of the envelope is the function identifier,
    /// and each assertion on the envelope is a parameter. Each parameter assertion
    /// is an identifer-value pair.
    public var envelope: Envelope {
        // When the `value` of an assertion is `nil`, as is the case with the
        // optional `path` argument, the `addAssertion` call returns the same
        // envelope. In other words, assertions with `nil` objects are not added
        // at all, and this extends to parameter assertions with `nil` values.
        //
        // Practically speaking, this means that if there is no `path` argument,
        // the resulting envelope will not have a `path` parameter assertion.
        try! Envelope(function: Self.function)
            .addAssertion(.parameter(.message, value: messageString))
            .addAssertion(.parameter(.path, value: path))
    }

    /// This method decodes an envelope into a body of this type. When this is called,
    /// the function has already been validated to be the correct type for this body.
    public init(_ envelope: Envelope) throws {
        /// The `message` argument is required, so this line will throw an exception unless
        /// exactly one `message` parameter is present and resolves to a well-formed string.
        let messageString = try envelope.extractObject(String.self, forParameter: .message)
        
        /// The `path` argument is optional, so the `path` variable below will be `nil`
        /// unless exactly one `path` parameter is present and resolves to a well-formed
        /// `DerivationPath`.
        let path = try? envelope.extractObject(DerivationPath.self, forParameter: .path)

        self.init(messageString: messageString, path: path)
    }
}

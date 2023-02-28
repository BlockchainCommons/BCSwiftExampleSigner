import Foundation
import BCFoundation
import WolfBase

/// This is an example signing service: it receives messages and signs them with the
/// private keys it contains.
public struct ExampleSigner {
    /// This is the key the service uses to sign the messages it's given. It could be a
    /// single key stored on an airgapped device or a database of seeds from which
    /// one will be selected by some means for each signing.
    let masterKey: HDKey

    /// Creates a signer instance. It stores a single master HD key generated from the
    /// provided seed.
    public init(seed: Seed) {
        self.masterKey = try! HDKey(seed: seed)
    }

    /// This is the internal function that takes an arbitrary binary message and signs
    /// it with a key derived from the master key. If no derivation path is provided,
    /// then the master key itself is used for signing.
    func sign(message: Data, path: DerivationPath? = nil) -> Data {
        let derivedKey: HDKey
        if let path {
            derivedKey = try! HDKey(parent: masterKey, childDerivationPath: path)
        } else {
            derivedKey = masterKey
        }
        return derivedKey.ecPrivateKey!.ecdsaSign(message: message)
    }

    /// This type represents errors thrown by the signing service. For now the only
    /// case, `.invalidMessage` is used when the passed-in message fails validation.
    enum Error: LocalizedError {
        case invalidMessage

        var errorDescription: String? {
            switch self {
            case .invalidMessage:
                return "Invalid message."
            }
        }
    }
}

extension ExampleSigner {
    /// This is a function that implements ColdCard signing:
    /// https://coldcard.com/docs/sign-text-file
    ///
    /// It performs validation on the passed-in string, and then returns the same sort
    /// of signed message string that ColdCard would return.
    ///
    /// ⚠️ This has *not* yet been tested for actual ColdCard compatibility.
    func coldCardSign(message: String, path: DerivationPath? = nil) throws -> String {
        /// Up to 240 characters long.
        guard message.count <= 240 else {
            throw Error.invalidMessage
        }

        /// ASCII only and no control characters (code points 32 to 127).
        guard message.allSatisfy({
            (32...127).contains($0.unicodeScalars.first!.value)
        }) else {
            throw Error.invalidMessage
        }

        /// No more than 4 consecutive spaces
        guard !message.contains(try Regex(" {5}")) else {
            throw Error.invalidMessage
        }

        /// Leading and trailing whitespace will be trimmed
        let trimmedMessage = message.trim()

        /// Newline characters are stripped
        let strippedMessage = trimmedMessage.filter({ !$0.isNewline })

        /// Perform the actual signing.
        let signature = sign(message: message.utf8Data, path: path)

        /// Compose and return the result.
        let result = """
        -----BEGIN BITCOIN SIGNED MESSAGE-----
        \(strippedMessage)
        -----BEGIN SIGNATURE-----
        \(signature.base64)
        -----END BITCOIN SIGNED MESSAGE-----
        """
        return result
    }
}

extension ExampleSigner {
    /// This is the top-level request router. It takes an Envelope in UR format and
    /// returns a response envelope, also in UR format. This function is marked `async`
    /// to model the asynchronous nature of a network call, although this example
    /// performs no actual asynchronous work.
    public func handleRequest(_ urString: String) async -> String {
        /// The transaction request ID is encoded in the UR, so we might not
        /// even get one if the UR is malformed.
        var transactionID: CID!

        /// The response envelope that will be returned to the caller.
        var response: Envelope!

        /// An exception thrown from this context will be transformed into an error envelope.
        do {
            /// Parse the UR into an envelope.
            let requestEnvelope = try Envelope(urString: urString)

            /// Parse the envelope into a request. The body envelope will be passed to
            /// the closure, which will parse the request body based on the request's
            /// function identifier.
            let request = try TransactionRequest(requestEnvelope) { bodyEnvelope in
                let function = try bodyEnvelope.extractSubject(Function.self)
                switch function {
                case ColdCardSignatureRequestBody.function:
                    return try ColdCardSignatureRequestBody(bodyEnvelope)
                default:
                    return nil
                }
            }

            /// At this point we know we have a well-formed request, we can get the request ID,
            /// which will be placed into our response.
            transactionID = request.id

            /// The request body will be a different type for each call. Each arm of this
            /// switch statement will perform the work it is asked to do. Right now there
            /// is only a single arm.
            switch request.body {
            case let body as ColdCardSignatureRequestBody:
                /// Perform the ColdCard signing, which uses the `message` string
                /// in the request body and results in another string to be
                /// returned to the caller.
                let result = try coldCardSign(message: body.messageString)
                /// Put the transaction ID and result into a response envelope.
                response = Envelope(response: transactionID, result: result)
            default:
                /// This wasn't a call we recognized.
                throw TransactionRequestError.unknownRequestType
            }
        } catch {
            if let transactionID {
                /// Something went wrong when performing the request.
                response = Envelope(response: transactionID, error: error.localizedDescription)
            } else {
                /// Something went wrong when parsing the UR or the envelope within.
                response = Envelope(error: error.localizedDescription)
            }
        }

        /// Return the response envelope as a UR string.
        return response.urString
    }
}

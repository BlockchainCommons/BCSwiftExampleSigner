import XCTest
import ExampleSigner
import BCFoundation
import WolfBase

final class ExampleSignerTests: XCTestCase {
    /// A CID for us to use as a transaction ID. Normally this would be random,
    /// but we're using a constant for testing purposes.
    static let transactionID = CID(‡"ab28955a997a8a096d0dd0b3d0833e494102d312e31be3005f32238921483170")!
    
    /// The seed that will be used to generate the signer's private key.
    static let seed = try! Seed(urString: "ur:crypto-seed/oyadgdylcackrsolbwhkcezmlahyrpetnbhsztjkaedwdw")
    
    /// The signer, initialized with our seed.
    static let signer = ExampleSigner(seed: seed)
    
    /// The `FormatContext` structure is used to inform the `Envelope` formatting
    /// commands about the names of known tags, functions, and parameters.
    ///
    /// In this example we don't need to add entries for our `Function` or `Parameter`
    /// instances because they are encoded as strings (see their definitions in
    /// `SignatureRequestBody.swift`) and are therefore human readable.
    static let formatContext = FormatContext(tags: knownTags)

    /// In this example, a message is sent to the signing service to be signed in a
    /// ColdCard-compatible way. No `path` argument is provided, so the signer will use
    /// the master key to sign.
    func testExample1() async throws {
        /// The message to be signed.
        let message = "to-be-signed"
        
        /// Create a message body which requests the message be signed using the ColdCard
        /// method.
        let body = ColdCardSignatureRequestBody(messageString: message)
        
        /// Place the body into a `TransactionRequest`. This structure includes a unique
        /// transaction ID, and optionally includes a timestamp and a human-readable note
        /// that, if present, should be displayed by an airgapped device before signing.
        let request = TransactionRequest(id: Self.transactionID, body: body, note: "Please sign me!")
        
        /// Transform the request structure into an envelope. In envelope notation, function
        /// identifiers are delimited by «double chevrons» and parameter identifiers are
        /// delimited by ❰single chevrons❱. These are actually a shorthand for specific CBOR
        /// tags.
        let requestEnvelope = request.envelope
        XCTAssertEqual(requestEnvelope.format(context: Self.formatContext),
        """
        request(CID(ab28955a)) [
            body: «"coldCardSign"» [
                ❰"message"❱: "to-be-signed"
            ]
            note: "Please sign me!"
        ]
        """)

        /// Encode the envelope as a UR. This is the actual data that would be placed into a
        /// (possibly animated) QR code. (For efficiency, always transform URs to UPPERCASE
        /// before actually QR encoding them.)
        let requestURString = requestEnvelope.urString
        XCTAssertEqual(requestURString, "ur:envelope/lstpsptpcstptstpsghdcxpydemdhtnlknleasjnbttiqdtilsfmgafpaotebgvlcwvlaeheeycnldclfdehjotpsptputlftpsptpuraatpsptpcsjlgdjzihhsjkihcxjkiniojtcxjnihcltpsptputlftpsptpurcsietpsplftpsptpcstptljziajljziefxhsjpieguiniojttpsptputlftpsptpcstptbiojnihjkjkhsioihtpsptpcsjzjyjldpidihdpjkiniojtihierttplefn")
        
        /// Send the request to the signing service endpoint via a REST call or QR code. The
        /// response is sent back as a UR string. `handleRequest` is an `async` call and so
        /// is marked here with `await` in order to simulate the asynchronous nature of a
        /// network call, although this example performs no actual asynchonous work.
        let responseURString = await Self.signer.handleRequest(requestURString)
        
        /// Parse the UR string into an envelope.
        let response = try Envelope(urString: responseURString)

        /// Examine the returned envelope. It looks a bit odd because the `result` string is
        /// actually several lines of text including newlines.
        XCTAssertEqual(response.format(context: Self.formatContext),
        #"""
        response(CID(ab28955a)) [
            result: "-----BEGIN BITCOIN SIGNED MESSAGE-----\nto-be-signed\n-----BEGIN SIGNATURE-----\ntO6gtPqsxwC65X6MxBhqsxWcOols9ijIDZ3G8nZlCO9hUFiHq1bhe08M+8XLPdXSuu3hO7r4/QW8BcVnQnqtAw==\n-----END BITCOIN SIGNED MESSAGE-----"
        ]
        """#)

        /// Extract the ColdCard-signed message out of the response envelope.
        /// This is what the ColdCard user would expect to see.
        let signedMessage = try response.result(String.self)
        XCTAssertEqual(signedMessage,
        """
        -----BEGIN BITCOIN SIGNED MESSAGE-----
        to-be-signed
        -----BEGIN SIGNATURE-----
        tO6gtPqsxwC65X6MxBhqsxWcOols9ijIDZ3G8nZlCO9hUFiHq1bhe08M+8XLPdXSuu3hO7r4/QW8BcVnQnqtAw==
        -----END BITCOIN SIGNED MESSAGE-----
        """)
    }
    
    /// The only difference between this and the previous example is the inclusion of a
    /// `path` argument.
    func testExample2() async throws {
        let message = "to-be-signed"

        /// Note that `DerivationPath` is not a string: it is a compound type that can parse,
        /// validate and output path strings, and contains a sequence of `DerivationSteps`
        /// that make for easy handling of the path in code, including ranges and wildcards.
        /// It also conforms to `CBORTaggedCodable`, and therefore seamlessly integrates
        /// with envelope encoding.
        let path = DerivationPath(string: "23/23'/33")!

        /// Examine the CBOR diagnostic notation of the path. The format is described
        /// [here](https://github.com/BlockchainCommons/Research/blob/master/papers/bcr-2020-007-hdkey.md#cddl-for-key-path)
        XCTAssertEqual(path.cbor.diagnostic(annotate: true, knownTags: knownTags),
        """
        304(   ; crypto-keypath
           {
              1:
              [23, false, 23, true, 33, false]
           }
        )
        """)
        
        /// Examine the CBOR encoding of the path.
        XCTAssertEqual(path.cbor.hex(annotate: true, knownTags: knownTags),
        """
        d9 0130       # tag(304)   ; crypto-keypath
           a1         # map(1)
              01      # unsigned(1)
              86      # array(6)
                 17   # unsigned(23)
                 f4   # false
                 17   # unsigned(23)
                 f5   # true
                 1821 # unsigned(33)
                 f4   # false
        """)
        
        let body = ColdCardSignatureRequestBody(messageString: message, path: path)
        let request = TransactionRequest(id: Self.transactionID, body: body)
        let requestEnvelope = request.envelope
        XCTAssertEqual(requestEnvelope.format(context: Self.formatContext),
        """
        request(CID(ab28955a)) [
            body: «"coldCardSign"» [
                ❰"message"❱: "to-be-signed"
                ❰"path"❱: crypto-keypath(Map)
            ]
        ]
        """)

        /// Encode the envelope as a UR. This is the actual data that would be placed into a
        /// (possibly animated) QR code. (For efficiency, always transform URs to UPPERCASE
        /// before actually QR encoding them.)
        let requestURString = requestEnvelope.urString
        XCTAssertEqual(requestURString, "ur:envelope/lftpsptpcstptstpsghdcxpydemdhtnlknleasjnbttiqdtilsfmgafpaotebgvlcwvlaeheeycnldclfdehjotpsptputlftpsptpurcsietpsplstpsptpcstptljziajljziefxhsjpieguiniojttpsptputlftpsptpcstptbiojnihjkjkhsioihtpsptpcsjzjyjldpidihdpjkiniojtihietpsptputlftpsptpcstptbiejohsjyistpsptpcstaaddyoyadlnchwkchykcsclwkdpdpynec")
        
        /// Send the request to the signing service endpoint via a REST call or QR code.
        /// The response is sent back as a UR string.
        let responseURString = await Self.signer.handleRequest(requestURString)
        
        /// Parse the UR string into an envelope.
        let response = try Envelope(urString: responseURString)
        print(response.format(context: Self.formatContext))
        let signedMessage = try response.result(String.self)
        XCTAssertEqual(signedMessage,
        """
        -----BEGIN BITCOIN SIGNED MESSAGE-----
        to-be-signed
        -----BEGIN SIGNATURE-----
        tO6gtPqsxwC65X6MxBhqsxWcOols9ijIDZ3G8nZlCO9hUFiHq1bhe08M+8XLPdXSuu3hO7r4/QW8BcVnQnqtAw==
        -----END BITCOIN SIGNED MESSAGE-----
        """)
    }
    
    /// This example shows what happens when a malformed request is included. In this
    /// case, the ColdCard rules state that only up to four consecutive spaces are
    /// allowed, so here we include five.
    func testExample3() async throws {
        let message = "to-be-     signed"
        let body = ColdCardSignatureRequestBody(messageString: message)
        let request = TransactionRequest(id: Self.transactionID, body: body)
        let requestEnvelope = request.envelope
        XCTAssertEqual(requestEnvelope.format(context: Self.formatContext),
        """
        request(CID(ab28955a)) [
            body: «"coldCardSign"» [
                ❰"message"❱: "to-be-     signed"
            ]
        ]
        """)
        
        let requestURString = requestEnvelope.urString
        let responseURString = await Self.signer.handleRequest(requestURString)
        let response = try Envelope(urString: responseURString)

        /// Instead of a `result` assertion, this envelope includes an `error` assertion.
        XCTAssertEqual(response.format(context: Self.formatContext),
        """
        response(CID(ab28955a)) [
            error: "Invalid message."
        ]
        """)

        /// The envelope API provides conveniences for extracting result and error responses
        /// from envelopes.
        let errorMessage = try response.error(String.self)
        XCTAssertEqual(errorMessage, "Invalid message.")
    }
}

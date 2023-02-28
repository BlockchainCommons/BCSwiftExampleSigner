# ExampleSigner

## by Wolf McNally for Blockchain Commons

This Swift Package is an example of a Bitcoin-based (ECDSA) message signing service. It uses [Gordian Envelope](https://github.com/BlockchainCommons/Gordian/tree/master/Envelope) as the transport encoding for requests and responses. Envelope in turn uses [deterministic CBOR (dCBOR)](https://github.com/BlockchainCommons/BCSwiftDCBOR). Also demonstrated is the [Uniform Resource (UR)](https://github.com/BlockchainCommons/URKit) format.

The main source files of this project are heavily commented. It is suggested that the reader start by reading the unit tests in [ExampleSignerTests](Tests/ExampleSignerTests/ExampleSignerTests.swift) to understand how a client might use the signing service, then examine the [ExampleSigner](Sources/ExampleSigner/ExampleSigner.swift) file to see how it is implemented, and finally the [SignatureRequestBody](Sources/ExampleSigner/SignatureRequestBody.swift) file to see how the envelope-based messages are structured. 

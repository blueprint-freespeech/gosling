# Honk-RPC v0.1.0

#### Richard Pospesel <[richard@blueprintforfreespeech.org](mailto:richard@blueprintforfreespeech.org)>

#### Morgan <[morgan@torproject.org](mailto:morgan@torproject.org)>

---

Honk-RPC is a remote procedure call protocol.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",  "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119[^1].

Honk-RPC has the following properties:

- **Bi-Directional**: The participants in a Honk-RPC session MAY simultaneously make requests and receive requests, regardless of who has originally connected to whom.
- **Asynchronous**: Remote procedure calls are asynchronous by default. Requests MAY be either be resolved immediately or some time in the future. Requests MAY be executed out-of-order, executed concurrently, or scheduled for execution at a later date. How and when requests are executed are undefined implementation details.
- **Dynamic**: There is no pre-compiled interface definition. Users of the Honk-RPC protocol MUST implement their own method for determining which remote procedure calls are available. There are no built-in or standard remote procedure calls.
- **Binary Format**: The Honk-RPC data format is version 1.1 binary-json (BSON) documents. All data-types mentioned in this specification refer to BSON data-types[^2].
- **Transport Agnostic**: No assumptions are made about the underlying transport method used to transmit Honk-RPC communications. The transport method MUST handle all aspects of correctly routing Honk-RPC communications to the right session.

## Protocol

All Honk-RPC requests and responses are encoded as BSON documents. Honk-RPC BSON documents MUST conform to a particular schema described here.

Some fields are optional, while others are required. Honk-RPC BSON documents MUST contain all required fields.

Any unexpected fields found in a Honk-RPC document MUST be ignored.

### Messages

The base Honk-RPC BSON document type is a `message`. A `message` MUST contain a non-empty list of BSON documents. Each of these documents MUST be a valid `section`.

Because each `message` can contain more than one `section` objects, multiple requests, responses, or errors MAY be batched together and sent at once. The order in which `section` objects are handled is an undefined implementation detail.

The key/values defined in the various message format sections in this specification are listed in a particular order for illustrative purposes only. In reality, these fields MAY be arbitrarily ordered in memory.

#### Message Format

```
document message {
  // the Honk-RPC protocol version number
  [[required]] int32_t honk_rpc;
  // an array of section objects
  [[required]] document sections[];
}
```

The `honk_rpc` field is the Honk-RPC version supported by the `message` sender. Honk-RPC follows the Semantic Versioning 2.0.0 specification[^3]. The major, minor, and patch values are encoded as unsigned bytes within the signed 32-bit integer `honk_rpc`.

The following pseudo-code demonstrates conversion between these two representations:

```
pub fn semver_to_i32(major: u8, minor: u8, patch: u8) -> i32 {
    let major = major as i32;
    let minor = minor as i32;
    let patch = patch as i32;
    (major << 16) | (minor << 8) | patch
}

pub fn i32_to_semver(ver: i32) -> (u8, u8, u8) {
    let major = (ver & 0xff0000) >> 16;
    let minor = (ver & 0xff00) >> 8;
    let patch = ver & 0xff;
    (major as u8, minor as u8, patch as u8)
}
```

This representation *does* necessitate that the Honk-RPC protocol semantic version components never exceed the value 255. Implementations MUST verify they can correctly handle the Honk-RPC version. Receiving a `message` with an incompatible `honk_rpc` field SHALL be treated as fatal error.

### Sections

Honk-RPC defines three types of `section` object: `error`, `request` or `response`. Each `section` object is a document with the following format:

#### Section Format

```
document section {
  // the id is used to determine which type of section this document is:
  //  0 => error
  //  1 => request
  //  2 => response
  [[required]] int32_t id;
  // section-specific data
}
```

#### Error Section

An `error_section` MAY be sent in response to a request or due to an unrelated runtime error.

Each `error_section` MUST have an error code field. An error code is a 32-bit signed integer.

Some error codes indicate a fatal error. The sender of a fatal error MUST end the session after sending one, and the receiver of a fatal error MUST end the session after receiving one.

Negative error codes are reserved for protocol errors. Protocol errors SHALL be fatal.

Zero is not a valid error code and SHALL be treated as fatal.

Positive codes are reserved for application-specific errors. Such errors
MAY be either fatal or non-fatal depending on what is appropriate for the application. How non-fatal errors should be handled is up to the application developer and outside the scope of the Honk-RPC protocol.

#### Error Section Format

```
typedef enum class error_code : int32_t {
  // failure to parse a received BSON document
  bson_parse_failed            = -1,
  // received message document was too big; the default maximum message size
  // is 4096 bytes, but can be adjusted
  message_too_big              = -2,
  // received message document missing required fields
  message_parse_failed         = -3,
  // received message contained version the receiver cannot handle
  message_version_incompatible = -4,
  // section in received message contains unknown id
  section_id_unknown           = -5,
  // section in received message missing required field, or provided
  // field is wrong datatype
  section_parse_failed         = -6,
  // provided request cookie is already in use
  request_cookie_invalid       = -7,
  // provided request namespace does not exist
  request_namespace_invalid    = -8,
  // provided request function does not exist within the provided namespace
  request_function_invalid     = -9,
  // provided request version does not exist
  request_version_invalid      = -10,
  // provided response cookie is not recognized
  response_cookie_invalid      = -11,
  // provided response state is not valid
  response_state_invalid       = -12,
} error_code_t;

document error_section {
  // id for error_section
  [[required]] int32_t id = 0;
  // request cookie associated with a previous request; only present for
  // errors that can be associated with a previous request
  [[optional]] int64_t cookie;
  // the error code
  [[required]] error_code_t code;
  // human-readable message associated with this error
  [[optional]] string message;
  // primitive or structured debug data associated with with this error
  [[optional]] element data;
}
```
#### Request Section

Remote procedure calls are made by submitting a message with a `request_section`. The requestor MAY provide a cookie to associate with future response messages. If no cookie is provided, the remote procedure call SHALL be carried out but no response is sent.

Re-using a `cookie` value which is already associated with an in-process request MUST result in a fatal error.

Function arguments must be validated by the application developer.

```
document request_section {
  // id for request_section
  [[required]] int32_t id = 1;
  // request cookie used to associate a future response to this request. If a
  // cookie is not provided, the receiver must not return a response section.
  // It is up to the requestor to avoid cookie collisions (cookies are scoped
  // by session, so concurrent requests from multiple requestors may use
  // identical cookies without issue).
  [[optional]] int64_t cookie;
  // function namespace; if not provided assumed to the global/empty ""
  // namespace
  [[optional]] string namespace;
  // name of function to call; must not be empty string
  [[required]] string function;
  // the version of the function to call; if not provided assumed to be 0
  [[optional]] int32_t version;
  // a document containing arguments for the function; not required for a
  // function which takes no arguments
  [[optional]] document arguments;
}
```

#### Response Section

After handling a `request_section` with a valid `cookie` field, a `response_section` MUST be sent in response. Long-running operations MAY return a `response_section` with the state set to 'pending' and send a 'complete' response at a later date. Short-running operations MAY only send one response with the 'complete' state.

In the event of a runtime (non-protocol) error, a `response_section` SHALL not be returned and an `error_section` is returned instead.

```
typedef enum class request_state : int32_t {
  // request started and result is pending
  pending = 0,
  // request is complete
  complete = 1,
} request_state;

document response_section {
  // id for request_section
  [[required]] int32_t id = 2;
  // the cookie associated with a previous request this response document
  // refers to
  [[required]] int64_t cookie;
  // the current state of function execution
  [[required]] request_state_t state;
  // the primitive or structured return from the request associated with
  // 'cookie'; MAY be present if state is complete, MUST NOT be present
  // if state is pending
  [[optional]] element result;
}
```

## Acknowledgements

Creation of innovative free software needs support. We thank the NGI Assure Fund, a fund established by NLnet with financial support from the European Commission's Next Generation Internet programme, under the aegis of DG Communications Networks, Content and Technology under grant agreement No 957073

[^1]: RFC 2119: [https://www.rfc-editor.org/rfc/rfc2119](https://www.rfc-editor.org/rfc/rfc2119)
[^2]: BSON spec: [https://bsonspec.org/spec.html](https://bsonspec.org/spec.html)
[^3]: Semantic Versioning 2.0.0 spec: [https://semver.org/spec/v2.0.0.html](https://semver.org/spec/v2.0.0.html)
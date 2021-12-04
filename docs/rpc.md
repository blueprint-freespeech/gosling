# Honk RPC v1

Honk RPC is an asynchronous, bi-directional, dynamic, binary remote procedure call interface:
- **asynchronous**: All procedures are asynchronous by default
- **bi-directional**: Each participant in a Honk session may simultaneously act as both a server and a client, regardless of who has connected to whom; both parties may call procedures on the other
- **dynamic**: The procedure interface is dynamic, in that it is up to the receiver to route function call requests. There is no pre-compiled interface definition.
- **binary**: Underlying messages are encoded in version 1.1 binary-json (BSON)[^1]

## Making Method Calls

Objects specified here are BSON documents using BSON data-types. Unexpected members on any of these defined objects must be ignored by implementations.

### Object format for messages

All `message` objects have the following format.

```c++
document message {
    // the Honk RPC version number
    [[required]] byte honk_rpc;
    // if true, error sections sent as a response to this message may also
    // return human-readable errors or additional debug data; when not
    // present assumed to be false
    [[optional]] boolean verbose;
    // an array of BSON documents, each document containing a message section
    // multiple sections can therefore be sent in a single message
    [[required]] document sections[];
}
```

### Sections

Each section contains the following in-line header:

```c++
{
    // the id is used to determine which type of section this document is
    [[required]] byte id;
}
```

#### Error Section

An `error_section` may be sent in response to a request, or due to an unrelated runtime error.

Error codes are 32-bit signed integers. **Negative** error codes are reserved for **protocol errors**, while **positive** codes are reserved for per-application, developer-defined **runtime errors**.

Negative (protocol) errors are fatal, and the sender must terminate the connection after sending one. Positive (runtime) errors are application specific, and should be handled accordingly by the application developer.

Function arguments must be validated by the application developer.

```c++
typedef enum class error_code : int32_t {
    // failure to parse a received BSON object
    bson_parse_failed            = -1,

    // received message document was too big; the default maximum message size
    // is 4Kib, but can be adjusted
    message_too_big              = -2,
    // received message document missing required members
    message_parse_failed         = -3,
    // received message contained version the receiver cannot handle
    message_version_incompatible = -4,

    // section in received message contains unknown id
    section_id_unknown           = -5,
    // section in received message missing required member, or provided
    // member is wrong datatype
    section_parse_failed         = -6,

    // provided request cookie is already in use
    request_cookie_invalid       = -7
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
    [[required]] byte id = 0x00;
    // request cookie associated with a previous request; only present for
    // errors that can be associated with a previous request
    [[optional]] uint64_t cookie;
    // the error code
    [[required]] error_code_t code;
    // human-readable message associated with this error
    [[optional]] string message;
    // primitive or structured debug data associated with with this error
    [[optional]] document data;
}
```
#### Request Section

Remote procedure calls are made by submitting a message with a `request_section`. The requestor may provide a cookie to associate with future response messages. If no cookie is provided, the request is carried out but no response is sent.

```c++
document request_section {
    // id for request_section
    [[required]] byte id = 0x01;
    // request cookie used to associate a future response to this request. If a
    // cookie is not provided, the receiver must not return a response section.
    // It is up to the requestor to avoid cookie collisions (cookies are scoped
    // by session, so concurrent requests from multiple requestors may use
    // identical cookies without issue).
    [[optional]] uint64_t cookie;
    // function namespace; if not provided assumed to the global/empty ""
    // namespace
    [[optional]] string namespace;
    // name of function to call
    [[required]] string function;
    // the version of the function to call; if not provided assumed to be 0
    [[optional]] byte version;
    // a document containing arguments for the function; not required for a
    // function which has no arguments
    [[optional]] document arguments;
}
```

#### Response Section

After receiving a message with a `request_section`, a message with a `response_section` is sent in response. Long-running operations may return a `response_section` with the state set to 'pending' and send a 'complete' response at a later date. Short-running operations may only send one response with the 'complete' state.

In the event of a runtime (non-protocol) error, a `response_section` is not returned and an `error_section` is instead.

```c++
typedef enum class request_state : byte {
    // request started and result is pending
    pending = 0,
    // request is complete
    complete = 1,
} request_state;

document response_section {
    // id for request_section
    [[required]] byte id = 0x02;
    // the cookie associated with a previous request this response document
    // refers to
    [[required]] uint64_t cookie;
    // the current state of function execution
    [[required]] request_state_t state;
    // the primitive or structured return from the request associated with
    // 'cookie'
    [[optional]] element result;
}
```

## Built-in Functions

Honk RPC defines its own `honk_rpc` namespace for the following built-in functions. The version for each function is `0` unless otherwise stated.

```c++
namespace honk_rpc {
    // Gets the maximum size message the receiver will accept
    //
    // returns: Largest message receiver will accept in bytes; a value
    // of 0 indicates no maximum size
    get_maximum_message_size() -> uint32_t;

    // Try and set the maximum message size
    //
    // params:
    // - uint32_t size: proposed maximum number of bytes a sent message can be;
    //   a value of 0 indicates no maximum size
    //
    // returns: largest message receiver will accept in bytes
    try_set_maximum_message_size(uint32_t size) -> uint32_t;

    // Gets the amount of time in milliseconds the receiver is willing
    // to wait between function calls before closing the connection
    //
    // returns: timeout period in milliseconds; a value of 0 indicates no
    // timeout
    get_timeout_period() -> uint32_t;

    // Try and set the maximum amount of time the receiver is willing
    // to wait between function calls  before closing the connection;
    //
    // params:
    // - uint32_t period: the number of milliseconds to wait before closing
    //   the underlying a transport. A value of 0 indicates no timeout.
    //
    // returns: timeout period in milliseconds; a value of 0 indicates no
    // timeout
    try_set_timeout_period(uint32_t period) -> uint32_t;

    // A no-op function which solely resets the receivers wait timer
    //
    // returns: the number of milliseconds since the last time the
    // the connection's wait timer was reset
    keep_alive() -> uint32_t;
}
```

[^1]: https://bsonspec.org/spec.html

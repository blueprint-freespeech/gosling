using namespace std;
using namespace gosling;

// gosling context

TEST_CASE("gosling_context_test") {
    unique_ptr<gosling_context> context;
    REQUIRE_NOTHROW(::gosling_context_init(
        out(context), // out_context
        "/tmp/gosling_context_test", // tor working dirctory
        sizeof("/tmp/gosling_context_test") - 1, // tor working directory len
        420,  // identity port
        420,  // endpoint port
        nullptr, // identity private key
        nullptr, // blocked clients,
        0, // blocked clients count
        nullptr, // client callbacks
        nullptr, // server callbacks
        throw_on_error()));
}
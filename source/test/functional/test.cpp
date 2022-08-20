using namespace std;
using namespace gosling;

// gosling context

TEST_CASE("gosling_context_test") {
    unique_ptr<gosling_context> context;
    gosling_context_init(
        out(context),
        420,  // identity port
        420,  // endpoint port
        nullptr, // identity private key
        nullptr, // blocked clients,
        0, // blocked clients count
        nullptr, // server started callback
        nullptr, // endpoint supported callback
        nullptr, // challenge size callback
        nullptr, // buil challenge callback
        nullptr, // started client callback
        nullptr, // challenge build response size callback
        nullptr, // challenge build response callback
        throw_on_error());
}
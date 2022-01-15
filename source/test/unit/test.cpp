#include <iostream>
#include <string>

#include <libgosling.hpp>

using namespace std;

int main(int argc, char** argv) try
{
    gosling_ed25519_private_key* privateKey = nullptr;
    const std::string keyBlob = "ED25519-V3:YE3GZtDmc+izGijWKgeVRabbXqK456JKKGONDBhV+kPBVKa2mHVQqnRTVuFXe3inU3YW6qvc7glYEwe9rK0LhQ==";
    ::gosling_ed25519_private_key_from_keyblob(&privateKey, keyBlob.c_str(), keyBlob.size(), gosling::throw_on_error());
}
catch(const std::runtime_error& err)
{
    cout << "Caught Error: " << err.what() << endl;
}
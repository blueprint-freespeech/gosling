#include <iostream>

#include <libgosling.h>

using namespace std;

int main(int argc, char** argv)
{
    auto retval = ::rust_hello_world();
    cout << "retval: " << retval << endl;

    gosling_error* perror = nullptr;
    ::gosling_example_work(&perror);

    cout << "perror: " << (void*)perror << endl;

    if (perror) {
        const auto msg = ::gosling_error_get_message(perror);

        cout << (void*)msg << endl;
        cout << "Message: " << msg << endl;

        ::gosling_error_free(perror);

        cout << "We still running though" << endl;
    }
}
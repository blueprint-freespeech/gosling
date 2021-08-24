#include <iostream>

#include <libgosling.h>

using namespace std;

int main(int argc, char** argv)
{
    auto retval = ::rust_hello_world();
    cout << "retval: " << retval << endl;
}
#include <iostream>

#include <libgosling.hpp>

using namespace std;

int main(int argc, char** argv) try
{
    auto retval = ::gosling_example_work(gosling::throw_on_error());
    cout << "retval: " << retval << endl;
}
catch(const std::runtime_error& err)
{
    cout << "Caught Error: " << err.what() << endl;
}
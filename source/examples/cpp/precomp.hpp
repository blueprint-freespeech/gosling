// C++
#include <algorithm>
#include <deque>
#include <functional>
#include <iostream>
#include <map>
#include <sstream>
#include <vector>
#include <iomanip>
#include <memory>

// boost
#include <boost/asio.hpp>

// ncurses
#if defined(CURSES_HAVE_NCURSES_H)
#  include <ncurses.h>
#elif defined(CURSES_HAVE_NCURSES_NCURSES_H)
#  include <ncurses/ncurses.h>
#else
    #error ncursess.h header required
#endif

// nlohmann
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// Gosling
#include <cgosling.hpp>

// platform specific wrappers for tcp stream stuffs
#if defined(GOSLING_PLATFORM_WINDOWS)
typedef SOCKET tcp_stream_t;
#elif (defined(GOSLING_PLATFORM_MACOS) || defined(GOSLING_PLATFORM_LINUX))
typedef int tcp_stream_t;
#endif

#pragma once

// c++
#include <stdexcept>

// gosling header
#include <libgosling.h>

namespace gosling {

    // Converts gosling_error_t** C style error handling to exceptions
    class throw_on_error
    {
    public:
        ~throw_on_error() noexcept(false)
        {
            if (error_ != nullptr)
            {
                std::runtime_error ex(gosling_error_get_message(error_));
                gosling_error_free(error_);
                error_ = nullptr;
                throw ex;
            }
        }

        operator gosling_error**()
        {
            return &error_;
        }
    private:
        gosling_error* error_ = nullptr;
    };
}

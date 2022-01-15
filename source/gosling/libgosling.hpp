#pragma once

// c++
#include <stdexcept>
#include <memory>

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

namespace std {
    template<> class default_delete<gosling_ed25519_private_key> {
    public:
        void operator()(gosling_ed25519_private_key *val) {
            gosling_ed25519_private_key_free(val);
        }
    };
    template<> class default_delete<gosling_ed25519_public_key> {
    public:
        void operator()(gosling_ed25519_public_key *val) {
            gosling_ed25519_public_key_free(val);
        }
    };
    template<> class default_delete<gosling_ed25519_signature> {
    public:
        void operator()(gosling_ed25519_signature *val) {
            gosling_ed25519_signature_free(val);
        }
    };
    template<> class default_delete<gosling_v3_onion_service_id> {
    public:
        void operator()(gosling_v3_onion_service_id *val) {
            gosling_v3_onion_service_id_free(val);
        }
    };
}
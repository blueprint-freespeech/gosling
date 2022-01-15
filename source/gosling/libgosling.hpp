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

    //
    // helper class for populating out T** params into unique_ptr<T> objects
    //
    template<typename T>
    class out_unique_ptr
    {
    public:
        out_unique_ptr() = delete;
        out_unique_ptr(const out_unique_ptr&) = delete;
        out_unique_ptr(out_unique_ptr&&) = delete;
        out_unique_ptr& operator=(const out_unique_ptr&) = delete;
        out_unique_ptr& operator=(out_unique_ptr&&) = delete;

        out_unique_ptr(std::unique_ptr<T>& u) : u_(u) {}
        ~out_unique_ptr()
        {
            u_.reset(t_);
        }

        operator T**()
        {
            return &t_;
        }

    private:
        T* t_ = nullptr;
        std::unique_ptr<T>& u_;
    };

    //
    // helper function for populating out T** params
    // example:
    //
    // void give_int(int** outInt);
    // std::unique_ptr<int> pint;
    // give_int(tego::out(pint));
    // int val = *pint;
    //
    template<typename T>
    out_unique_ptr<T> out(std::unique_ptr<T>& ptr)
    {
        return {ptr};
    }
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
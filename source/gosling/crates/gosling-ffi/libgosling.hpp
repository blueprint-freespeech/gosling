#pragma once

// c++
#include <memory>
#include <ostream>
#include <stdexcept>

// gosling header
#include <libgosling.h>

// we need to support client and server handshake handles being pointers in
// disguise
static_assert(sizeof(size_t) == sizeof(uintptr_t));

namespace gosling {

// Converts gosling_error_t** C style error handling to exceptions
class throw_on_error {
public:
  ~throw_on_error() noexcept(false) {
    if (error_ != nullptr) {
      std::runtime_error ex(gosling_error_get_message(error_));
      gosling_error_free(error_);
      error_ = nullptr;
      // cppcheck-suppress exceptThrowInDestructor
      throw ex;
    }
  }

  operator gosling_error **() { return &error_; }

private:
  gosling_error *error_ = nullptr;
};

//
// helper class for populating out T** params into unique_ptr<T> objects
//
template <typename T> class out_unique_ptr {
public:
  out_unique_ptr() = delete;
  out_unique_ptr(const out_unique_ptr &) = delete;
  out_unique_ptr &operator=(const out_unique_ptr &) = delete;
  out_unique_ptr &operator=(out_unique_ptr &&) = delete;

  out_unique_ptr(out_unique_ptr &&that) : t_(that.t_), u_(that.u_) {
    that.t_ = nullptr;
    that.u_ = nullptr;
  };
  explicit constexpr out_unique_ptr(std::unique_ptr<T> &u)
      : t_(nullptr), u_(&u) {}

  ~out_unique_ptr() {
    if (u_ != nullptr) {
      u_->reset(t_);
    }
  }

  constexpr operator T **() { return &t_; }

private:
  T *t_ = nullptr;
  std::unique_ptr<T> *u_ = nullptr;
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
template <typename T>
constexpr auto out(std::unique_ptr<T> &ptr) -> out_unique_ptr<T> {
  return out_unique_ptr<T>{ptr};
}

//
// std::ostream<< overloads for various gosling types
//

inline std::ostream &operator<<(std::ostream &stream,
                                const gosling_v3_onion_service_id *serviceId) {
  char serviceIdStringRaw[V3_ONION_SERVICE_ID_STRING_SIZE];
  ::gosling_v3_onion_service_id_to_string(serviceId, serviceIdStringRaw,
                                          sizeof(serviceIdStringRaw),
                                          gosling::throw_on_error());

  return stream.write(serviceIdStringRaw, sizeof(serviceIdStringRaw) - 1);
}

inline std::ostream &operator<<(std::ostream &stream,
                                const gosling_ed25519_private_key *privateKey) {
  char keyBlobRaw[ED25519_PRIVATE_KEY_KEYBLOB_SIZE];
  ::gosling_ed25519_private_key_to_keyblob(
      privateKey, keyBlobRaw, sizeof(keyBlobRaw), gosling::throw_on_error());

  return stream.write(keyBlobRaw, sizeof(keyBlobRaw) - 1);
}

inline std::ostream &operator<<(std::ostream &stream,
                                const gosling_x25519_private_key *privateKey) {
  char keyBlobRaw[X25519_PRIVATE_KEY_BASE64_SIZE];
  ::gosling_x25519_private_key_to_base64(
      privateKey, keyBlobRaw, sizeof(keyBlobRaw), gosling::throw_on_error());

  return stream.write(keyBlobRaw, sizeof(keyBlobRaw) - 1);
}

inline std::ostream &operator<<(std::ostream &stream,
                                const gosling_x25519_public_key *publicKey) {
  char keyBlobRaw[X25519_PUBLIC_KEY_BASE32_SIZE];
  ::gosling_x25519_public_key_to_base32(
      publicKey, keyBlobRaw, sizeof(keyBlobRaw), gosling::throw_on_error());

  return stream.write(keyBlobRaw, sizeof(keyBlobRaw) - 1);
}
} // namespace gosling

namespace std {
//
// default_delete implementation for unique_ptr of various gosling types
//
template <> class default_delete<gosling_library> {
public:
  void operator()(gosling_library *val) { gosling_library_free(val); }
};
template <> class default_delete<gosling_ed25519_private_key> {
public:
  void operator()(gosling_ed25519_private_key *val) {
    gosling_ed25519_private_key_free(val);
  }
};
template <> class default_delete<gosling_x25519_private_key> {
public:
  void operator()(gosling_x25519_private_key *val) {
    gosling_x25519_private_key_free(val);
  }
};
template <> class default_delete<gosling_x25519_public_key> {
public:
  void operator()(gosling_x25519_public_key *val) {
    gosling_x25519_public_key_free(val);
  }
};
template <> class default_delete<gosling_v3_onion_service_id> {
public:
  void operator()(gosling_v3_onion_service_id *val) {
    gosling_v3_onion_service_id_free(val);
  }
};
template <> class default_delete<gosling_tor_provider> {
public:
  void operator()(gosling_tor_provider *val) { gosling_tor_provider_free(val); }
};
template <> class default_delete<gosling_context> {
public:
  void operator()(gosling_context *val) { gosling_context_free(val); }
};
} // namespace std

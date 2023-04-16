using namespace std;
using namespace gosling;

// ed25519 Private Key

TEST_CASE("gosling_ed25519_private_key_generate") {
  unique_ptr<gosling_library> library;
  REQUIRE_NOTHROW(::gosling_library_init(out(library), throw_on_error()));

  unique_ptr<gosling_ed25519_private_key> privateKeyAlice;
  unique_ptr<gosling_ed25519_private_key> privateKeyPat;

  // no valid dest
  REQUIRE_THROWS(
      ::gosling_ed25519_private_key_generate(nullptr, throw_on_error()));

  // key generation should succeed
  REQUIRE_NOTHROW(::gosling_ed25519_private_key_generate(out(privateKeyAlice),
                                                         throw_on_error()));
  REQUIRE_NOTHROW(::gosling_ed25519_private_key_generate(out(privateKeyPat),
                                                         throw_on_error()));

  // generated keys should not be null
  REQUIRE(privateKeyAlice.get() != nullptr);
  REQUIRE(privateKeyPat.get() != nullptr);

  // generated keys should be different
  REQUIRE(privateKeyAlice.get() != privateKeyPat.get());

  // generated keys should have a different key blob representation
  char aliceKeyBlobRaw[ED25519_PRIVATE_KEYBLOB_SIZE] = {0};
  char patKeyBlobRaw[ED25519_PRIVATE_KEYBLOB_SIZE] = {0};
  REQUIRE_NOTHROW(::gosling_ed25519_private_key_to_keyblob(
      privateKeyAlice.get(), aliceKeyBlobRaw, ED25519_PRIVATE_KEYBLOB_SIZE,
      throw_on_error()));
  REQUIRE_NOTHROW(::gosling_ed25519_private_key_to_keyblob(
      privateKeyPat.get(), patKeyBlobRaw, ED25519_PRIVATE_KEYBLOB_SIZE,
      throw_on_error()));

  REQUIRE(strcmp(aliceKeyBlobRaw, patKeyBlobRaw) != 0);
}

TEST_CASE("gosling_ed25519_private_key_from_keyblob") {
  unique_ptr<gosling_library> library;
  REQUIRE_NOTHROW(::gosling_library_init(out(library), throw_on_error()));

  unique_ptr<gosling_ed25519_private_key> privateKey;
  const std::string keyBlob =
      "ED25519-V3:YE3GZtDmc+izGijWKgeVRabbXqK456JKKGONDBhV+"
      "kPBVKa2mHVQqnRTVuFXe3inU3YW6qvc7glYEwe9rK0LhQ==";
  const std::string invalidKeyBlob =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      "aaaaaaaaaaaaaaaaaaaaaaaaaaa";
  REQUIRE(keyBlob.size() == ED25519_PRIVATE_KEYBLOB_LENGTH);
  REQUIRE(invalidKeyBlob.size() == ED25519_PRIVATE_KEYBLOB_LENGTH);

  // no valid inputs
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(nullptr, nullptr, 0,
                                                            throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(nullptr, nullptr, 1,
                                                            throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      nullptr, nullptr, ED25519_PRIVATE_KEYBLOB_SIZE, throw_on_error()));

  // valid dest, invalid key blob, invaild key blob len
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      out(privateKey), nullptr, 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      out(privateKey), nullptr, 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      out(privateKey), nullptr, ED25519_PRIVATE_KEYBLOB_SIZE,
      throw_on_error()));

  // valid dest, valid key blob, invaild key blob len
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      out(privateKey), keyBlob.c_str(), 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      out(privateKey), keyBlob.c_str(), 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      out(privateKey), keyBlob.c_str(), ED25519_PRIVATE_KEYBLOB_SIZE,
      throw_on_error()));

  // invalid dest, valid key blob, invalid key blob len
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      nullptr, keyBlob.c_str(), 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      nullptr, keyBlob.c_str(), 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      nullptr, keyBlob.c_str(), ED25519_PRIVATE_KEYBLOB_SIZE,
      throw_on_error()));

  // invalid dest, valid key blob, valid key blob len
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      nullptr, keyBlob.c_str(), keyBlob.size(), throw_on_error()));

  // valid dest, invalid key blob, valid key blob len
  REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(
      out(privateKey), invalidKeyBlob.c_str(), invalidKeyBlob.size(),
      throw_on_error()));

  // valid dest, valid key blob, valid key blob len
  REQUIRE_NOTHROW(::gosling_ed25519_private_key_from_keyblob(
      out(privateKey), keyBlob.c_str(), keyBlob.size(), throw_on_error()));
  REQUIRE(privateKey.get() != nullptr);
}

TEST_CASE("gosling_ed25519_private_key_to_keyblob") {
  unique_ptr<gosling_library> library;
  REQUIRE_NOTHROW(::gosling_library_init(out(library), throw_on_error()));

  unique_ptr<gosling_ed25519_private_key> privateKey;
  const std::string keyBlob =
      "ED25519-V3:YE3GZtDmc+izGijWKgeVRabbXqK456JKKGONDBhV+"
      "kPBVKa2mHVQqnRTVuFXe3inU3YW6qvc7glYEwe9rK0LhQ==";
  char keyBlobRaw[ED25519_PRIVATE_KEYBLOB_SIZE] = {0};
  REQUIRE_NOTHROW(::gosling_ed25519_private_key_from_keyblob(
      out(privateKey), keyBlob.c_str(), keyBlob.size(), throw_on_error()));
  REQUIRE(privateKey.get() != nullptr);

  // no valid inputs
  REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(nullptr, nullptr, 0,
                                                          throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(nullptr, nullptr, 1,
                                                          throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(
      nullptr, nullptr, ED25519_PRIVATE_KEYBLOB_LENGTH, throw_on_error()));

  // valid key, invalid out key blob, invalid key blob size
  REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(
      privateKey.get(), nullptr, 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(
      privateKey.get(), nullptr, 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(
      privateKey.get(), nullptr, ED25519_PRIVATE_KEYBLOB_LENGTH,
      throw_on_error()));

  // valid key, valid out key blob, invalid key blob size
  REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(
      privateKey.get(), keyBlobRaw, 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(
      privateKey.get(), keyBlobRaw, 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(
      privateKey.get(), keyBlobRaw, ED25519_PRIVATE_KEYBLOB_LENGTH,
      throw_on_error()));

  // valid key, valid out key blob, valid key size
  REQUIRE_NOTHROW(::gosling_ed25519_private_key_to_keyblob(
      privateKey.get(), keyBlobRaw, sizeof(keyBlobRaw), throw_on_error()));
  REQUIRE(std::string(keyBlobRaw) == keyBlob);
}

// x25519 Private Key

TEST_CASE("gosling_x25519_private_key_from_base64") {
  unique_ptr<gosling_library> library;
  REQUIRE_NOTHROW(::gosling_library_init(out(library), throw_on_error()));

  unique_ptr<gosling_x25519_private_key> privateKey;
  const std::string base64 = "0GeSReJXdNcgvWRQdnDXhJGdu5UiwP2fefgT93/oqn0=";
  const std::string invalidBase64 =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  REQUIRE(base64.size() == X25519_PRIVATE_KEYBLOB_BASE64_LENGTH);
  REQUIRE(invalidBase64.size() == X25519_PRIVATE_KEYBLOB_BASE64_LENGTH);

  // no valid inputs
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(nullptr, nullptr, 0,
                                                          throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(nullptr, nullptr, 1,
                                                          throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      nullptr, nullptr, X25519_PRIVATE_KEYBLOB_BASE64_SIZE, throw_on_error()));

  // valid dest, invalid base64, invaild base64 len
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      out(privateKey), nullptr, 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      out(privateKey), nullptr, 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      out(privateKey), nullptr, X25519_PRIVATE_KEYBLOB_BASE64_SIZE,
      throw_on_error()));

  // valid dest, valid base64, invaild base64 len
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      out(privateKey), base64.c_str(), 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      out(privateKey), base64.c_str(), 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      out(privateKey), base64.c_str(), X25519_PRIVATE_KEYBLOB_BASE64_SIZE,
      throw_on_error()));

  // invalid dest, valid base64, invalid base64 len
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      nullptr, base64.c_str(), 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      nullptr, base64.c_str(), 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      nullptr, base64.c_str(), X25519_PRIVATE_KEYBLOB_BASE64_SIZE,
      throw_on_error()));

  // invalid dest, valid base64, valid base64 len
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      nullptr, base64.c_str(), base64.size(), throw_on_error()));

  // valid dest, invalid base64, valid base64 len
  REQUIRE_THROWS(::gosling_x25519_private_key_from_base64(
      out(privateKey), invalidBase64.c_str(), invalidBase64.size(),
      throw_on_error()));

  // valid dest, valid base64, valid base64 len
  REQUIRE_NOTHROW(::gosling_x25519_private_key_from_base64(
      out(privateKey), base64.c_str(), base64.size(), throw_on_error()));
  REQUIRE(privateKey.get() != nullptr);
}

TEST_CASE("gosling_x25519_private_key_to_base64") {
  unique_ptr<gosling_library> library;
  REQUIRE_NOTHROW(::gosling_library_init(out(library), throw_on_error()));

  unique_ptr<gosling_x25519_private_key> privateKey;
  const std::string base64 = "0GeSReJXdNcgvWRQdnDXhJGdu5UiwP2fefgT93/oqn0=";
  char base64Raw[X25519_PRIVATE_KEYBLOB_BASE64_SIZE] = {0};
  REQUIRE_NOTHROW(::gosling_x25519_private_key_from_base64(
      out(privateKey), base64.c_str(), base64.size(), throw_on_error()));
  REQUIRE(privateKey.get() != nullptr);

  // no valid inputs
  REQUIRE_THROWS(::gosling_x25519_private_key_to_base64(nullptr, nullptr, 0,
                                                        throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_to_base64(nullptr, nullptr, 1,
                                                        throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_to_base64(
      nullptr, nullptr, X25519_PRIVATE_KEYBLOB_BASE64_LENGTH,
      throw_on_error()));

  // valid key, invalid out base64, invalid base64 size
  REQUIRE_THROWS(::gosling_x25519_private_key_to_base64(
      privateKey.get(), nullptr, 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_to_base64(
      privateKey.get(), nullptr, 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_to_base64(
      privateKey.get(), nullptr, X25519_PRIVATE_KEYBLOB_BASE64_LENGTH,
      throw_on_error()));

  // valid key, valid out base64, invalid base64 size
  REQUIRE_THROWS(::gosling_x25519_private_key_to_base64(
      privateKey.get(), base64Raw, 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_to_base64(
      privateKey.get(), base64Raw, 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_private_key_to_base64(
      privateKey.get(), base64Raw, X25519_PRIVATE_KEYBLOB_BASE64_LENGTH,
      throw_on_error()));

  // valid key, valid out base64, valid base64 size
  REQUIRE_NOTHROW(::gosling_x25519_private_key_to_base64(
      privateKey.get(), base64Raw, sizeof(base64Raw), throw_on_error()));
  REQUIRE(std::string(base64Raw) == base64);
}

// x25519 Public Key

TEST_CASE("gosling_x25519_public_key_from_base32") {
  unique_ptr<gosling_library> library;
  REQUIRE_NOTHROW(::gosling_library_init(out(library), throw_on_error()));

  unique_ptr<gosling_x25519_public_key> publicKey;
  const std::string base32 =
      "AEXCBCEDJ5KU34YGGMZ7PVHVDEA7D7YB7VQAPJTMTZGRJLN3JASA";
  const std::string invalidBase32 =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  REQUIRE(base32.size() == X25519_PUBLIC_KEYBLOB_BASE32_LENGTH);
  REQUIRE(invalidBase32.size() == X25519_PUBLIC_KEYBLOB_BASE32_LENGTH);

  // no valid inputs
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(nullptr, nullptr, 0,
                                                         throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(nullptr, nullptr, 1,
                                                         throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      nullptr, nullptr, X25519_PUBLIC_KEYBLOB_BASE32_SIZE, throw_on_error()));

  // valid dest, invalid base32, invaild base32 len
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      out(publicKey), nullptr, 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      out(publicKey), nullptr, 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      out(publicKey), nullptr, X25519_PUBLIC_KEYBLOB_BASE32_SIZE,
      throw_on_error()));

  // valid dest, valid base32, invaild base32 len
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      out(publicKey), base32.c_str(), 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      out(publicKey), base32.c_str(), 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      out(publicKey), base32.c_str(), X25519_PUBLIC_KEYBLOB_BASE32_SIZE,
      throw_on_error()));

  // invalid dest, valid base32, invalid base32 len
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      nullptr, base32.c_str(), 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      nullptr, base32.c_str(), 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      nullptr, base32.c_str(), X25519_PUBLIC_KEYBLOB_BASE32_SIZE,
      throw_on_error()));

  // invalid dest, valid base32, valid base32 len
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      nullptr, base32.c_str(), base32.size(), throw_on_error()));

  // valid dest, invalid base32, valid base32 len
  REQUIRE_THROWS(::gosling_x25519_public_key_from_base32(
      out(publicKey), invalidBase32.c_str(), invalidBase32.size(),
      throw_on_error()));

  // valid dest, valid base32, valid base32 len
  REQUIRE_NOTHROW(::gosling_x25519_public_key_from_base32(
      out(publicKey), base32.c_str(), base32.size(), throw_on_error()));
  REQUIRE(publicKey.get() != nullptr);
}

TEST_CASE("gosling_x25519_public_key_to_base32") {
  unique_ptr<gosling_library> library;
  REQUIRE_NOTHROW(::gosling_library_init(out(library), throw_on_error()));

  unique_ptr<gosling_x25519_public_key> publicKey;
  const std::string base32 =
      "AEXCBCEDJ5KU34YGGMZ7PVHVDEA7D7YB7VQAPJTMTZGRJLN3JASA";
  char base32Raw[X25519_PUBLIC_KEYBLOB_BASE32_SIZE] = {0};
  REQUIRE_NOTHROW(::gosling_x25519_public_key_from_base32(
      out(publicKey), base32.c_str(), base32.size(), throw_on_error()));
  REQUIRE(publicKey.get() != nullptr);

  // no valid inputs
  REQUIRE_THROWS(::gosling_x25519_public_key_to_base32(nullptr, nullptr, 0,
                                                       throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_to_base32(nullptr, nullptr, 1,
                                                       throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_to_base32(
      nullptr, nullptr, X25519_PUBLIC_KEYBLOB_BASE32_LENGTH, throw_on_error()));

  // valid key, invalid out base32, invalid base32 size
  REQUIRE_THROWS(::gosling_x25519_public_key_to_base32(publicKey.get(), nullptr,
                                                       0, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_to_base32(publicKey.get(), nullptr,
                                                       1, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_to_base32(
      publicKey.get(), nullptr, X25519_PUBLIC_KEYBLOB_BASE32_LENGTH,
      throw_on_error()));

  // valid key, valid out base32, invalid base32 size
  REQUIRE_THROWS(::gosling_x25519_public_key_to_base32(
      publicKey.get(), base32Raw, 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_to_base32(
      publicKey.get(), base32Raw, 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_x25519_public_key_to_base32(
      publicKey.get(), base32Raw, X25519_PUBLIC_KEYBLOB_BASE32_LENGTH,
      throw_on_error()));

  // valid key, valid out base32, valid base32 size
  REQUIRE_NOTHROW(::gosling_x25519_public_key_to_base32(
      publicKey.get(), base32Raw, sizeof(base32Raw), throw_on_error()));
  REQUIRE(std::string(base32Raw) == base32);
}

// v3 onion service id

TEST_CASE("gosling_v3_onion_service_id_from_string") {
  unique_ptr<gosling_library> library;
  REQUIRE_NOTHROW(::gosling_library_init(out(library), throw_on_error()));

  unique_ptr<gosling_v3_onion_service_id> serviceId;
  const std::string serviceIdString =
      "6l62fw7tqctlu5fesdqukvpoxezkaxbzllrafa2ve6ewuhzphxczsjyd";
  const std::string invalidServiceIdString =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  REQUIRE(serviceIdString.size() == V3_ONION_SERVICE_ID_LENGTH);
  REQUIRE(invalidServiceIdString.size() == V3_ONION_SERVICE_ID_LENGTH);

  // no valid inputs
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(nullptr, nullptr, 0,
                                                           throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(nullptr, nullptr, 1,
                                                           throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      nullptr, nullptr, V3_ONION_SERVICE_ID_SIZE, throw_on_error()));

  // valid dest, invalid serviceIdString, invalid serviceIdString len
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      out(serviceId), nullptr, 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      out(serviceId), nullptr, 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      out(serviceId), nullptr, V3_ONION_SERVICE_ID_SIZE, throw_on_error()));

  // valid dest, valid serviceIdString, invalid serviceIdString len
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      out(serviceId), serviceIdString.c_str(), 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      out(serviceId), serviceIdString.c_str(), 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      out(serviceId), serviceIdString.c_str(), V3_ONION_SERVICE_ID_SIZE,
      throw_on_error()));

  // invalid dest, valid serviceIdString, invalid serviceIdString len
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      nullptr, serviceIdString.c_str(), 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      nullptr, serviceIdString.c_str(), 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      nullptr, serviceIdString.c_str(), V3_ONION_SERVICE_ID_SIZE,
      throw_on_error()));

  // invalid dest, valid serviceIdString, valid serviceIdString len
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      nullptr, serviceIdString.c_str(), serviceIdString.size(),
      throw_on_error()));

  // valid dest, invalid serviceIdString, valid serviceIdString len
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_string(
      out(serviceId), invalidServiceIdString.c_str(),
      invalidServiceIdString.size(), throw_on_error()));

  // valid dest, valid serviceIdString, valid serviceIdString len
  REQUIRE_NOTHROW(::gosling_v3_onion_service_id_from_string(
      out(serviceId), serviceIdString.c_str(), serviceIdString.size(),
      throw_on_error()));
  REQUIRE(serviceId.get() != nullptr);
}

TEST_CASE("gosling_v3_onion_service_id_from_ed25519_private_key") {
  unique_ptr<gosling_library> library;
  REQUIRE_NOTHROW(::gosling_library_init(out(library), throw_on_error()));

  const std::string privateKeyBlob =
      "ED25519-V3:YE3GZtDmc+izGijWKgeVRabbXqK456JKKGONDBhV+"
      "kPBVKa2mHVQqnRTVuFXe3inU3YW6qvc7glYEwe9rK0LhQ==";
  const std::string serviceIdString =
      "6l62fw7tqctlu5fesdqukvpoxezkaxbzllrafa2ve6ewuhzphxczsjyd";

  // golden path
  unique_ptr<gosling_ed25519_private_key> privateKey;
  REQUIRE_NOTHROW(::gosling_ed25519_private_key_from_keyblob(
      out(privateKey), privateKeyBlob.data(), privateKeyBlob.size(),
      throw_on_error()));

  unique_ptr<gosling_v3_onion_service_id> serviceId;
  REQUIRE_NOTHROW(::gosling_v3_onion_service_id_from_ed25519_private_key(
      out(serviceId), privateKey.get(), throw_on_error()));

  char serviceIdStringRaw[V3_ONION_SERVICE_ID_SIZE] = {0};
  REQUIRE_NOTHROW(::gosling_v3_onion_service_id_to_string(
      serviceId.get(), serviceIdStringRaw, sizeof(serviceIdStringRaw),
      throw_on_error()));

  REQUIRE(serviceIdString == serviceIdStringRaw);

  // invalid inputs
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_ed25519_private_key(
      nullptr, nullptr, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_ed25519_private_key(
      out(serviceId), nullptr, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_from_ed25519_private_key(
      nullptr, privateKey.get(), throw_on_error()));
}

TEST_CASE("gosling_v3_onion_service_id_to_string") {
  unique_ptr<gosling_library> library;
  REQUIRE_NOTHROW(::gosling_library_init(out(library), throw_on_error()));

  unique_ptr<gosling_v3_onion_service_id> serviceId;
  const std::string serviceIdString =
      "6l62fw7tqctlu5fesdqukvpoxezkaxbzllrafa2ve6ewuhzphxczsjyd";
  char serviceIdStringRaw[V3_ONION_SERVICE_ID_SIZE] = {0};
  REQUIRE_NOTHROW(::gosling_v3_onion_service_id_from_string(
      out(serviceId), serviceIdString.c_str(), serviceIdString.size(),
      throw_on_error()));
  REQUIRE(serviceId.get() != nullptr);

  // no valid inputs
  REQUIRE_THROWS(::gosling_v3_onion_service_id_to_string(nullptr, nullptr, 0,
                                                         throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_to_string(nullptr, nullptr, 1,
                                                         throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_to_string(
      nullptr, nullptr, V3_ONION_SERVICE_ID_LENGTH, throw_on_error()));

  // valid serviceId, invalid out serviceIdStringRaw, invalid serviceIdStringRaw
  // size
  REQUIRE_THROWS(::gosling_v3_onion_service_id_to_string(
      serviceId.get(), nullptr, 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_to_string(
      serviceId.get(), nullptr, 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_to_string(
      serviceId.get(), nullptr, V3_ONION_SERVICE_ID_LENGTH, throw_on_error()));

  // valid serviceId, valid out serviceIdStringRaw, invalid serviceIdStringRaw
  // size
  REQUIRE_THROWS(::gosling_v3_onion_service_id_to_string(
      serviceId.get(), serviceIdStringRaw, 0, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_to_string(
      serviceId.get(), serviceIdStringRaw, 1, throw_on_error()));
  REQUIRE_THROWS(::gosling_v3_onion_service_id_to_string(
      serviceId.get(), serviceIdStringRaw, V3_ONION_SERVICE_ID_LENGTH,
      throw_on_error()));

  // valid serviceId, valid out serviceIdStringRaw, valid serviceIdStringRaw
  // size
  REQUIRE_NOTHROW(::gosling_v3_onion_service_id_to_string(
      serviceId.get(), serviceIdStringRaw, sizeof(serviceIdStringRaw),
      throw_on_error()));
  REQUIRE(std::string(serviceIdStringRaw) == serviceIdString);
}

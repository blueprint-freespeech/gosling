using namespace std;
using namespace gosling;

TEST_CASE("gosling_ed25519_private_key_from_keyblob") {
    unique_ptr<gosling_ed25519_private_key> privateKey;
    const std::string keyBlob = "ED25519-V3:YE3GZtDmc+izGijWKgeVRabbXqK456JKKGONDBhV+kPBVKa2mHVQqnRTVuFXe3inU3YW6qvc7glYEwe9rK0LhQ==";
    REQUIRE(keyBlob.size() == ED25519_KEYBLOB_LENGTH);

    // no valid inputs
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(nullptr, nullptr, 0, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(nullptr, nullptr, 1, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(nullptr, nullptr, ED25519_KEYBLOB_SIZE, throw_on_error()));

    // valid dest, invalid key blob, invaild key blob len
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(out(privateKey), nullptr, 0, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(out(privateKey), nullptr, 1, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(out(privateKey), nullptr, ED25519_KEYBLOB_SIZE, throw_on_error()));

    // valid dest, valid key blob, invaild key blob len
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(out(privateKey), keyBlob.c_str(), 0, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(out(privateKey), keyBlob.c_str(), 1, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(out(privateKey), keyBlob.c_str(), ED25519_KEYBLOB_SIZE, throw_on_error()));

    // invalid dest, valid key blob, invalid key blob len
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(nullptr, keyBlob.c_str(), 0, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(nullptr, keyBlob.c_str(), 1, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(nullptr, keyBlob.c_str(), ED25519_KEYBLOB_SIZE, throw_on_error()));

    // invalid dest, valid key blob, valid key blob len
    REQUIRE_THROWS(::gosling_ed25519_private_key_from_keyblob(nullptr, keyBlob.c_str(), keyBlob.size(), throw_on_error()));

    // invalid dest, valid key blob, valid key blob len
    REQUIRE_NOTHROW(::gosling_ed25519_private_key_from_keyblob(out(privateKey), keyBlob.c_str(), keyBlob.size(), throw_on_error()));
    REQUIRE(privateKey.get() != nullptr);
}

TEST_CASE("gosling_ed25519_private_key_to_keyblob") {
    unique_ptr<gosling_ed25519_private_key> privateKey;
    const std::string keyBlob = "ED25519-V3:YE3GZtDmc+izGijWKgeVRabbXqK456JKKGONDBhV+kPBVKa2mHVQqnRTVuFXe3inU3YW6qvc7glYEwe9rK0LhQ==";
    char keyBlobRaw[ED25519_KEYBLOB_SIZE] = {0};

    // no valid inputs
    REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(nullptr, nullptr, 0, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(nullptr, nullptr, 1, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(nullptr, nullptr, ED25519_KEYBLOB_LENGTH, throw_on_error()));

    // valid key, invalid out key blob, invalid key blob size
    REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(privateKey.get(), nullptr, 0, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(privateKey.get(), nullptr, 1, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(privateKey.get(), nullptr, ED25519_KEYBLOB_LENGTH, throw_on_error()));

    // valid key, valid out key blob, invalid key blob size
    REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(privateKey.get(), keyBlobRaw, 0, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(privateKey.get(), keyBlobRaw, 1, throw_on_error()));
    REQUIRE_THROWS(::gosling_ed25519_private_key_to_keyblob(privateKey.get(), keyBlobRaw, ED25519_KEYBLOB_LENGTH, throw_on_error()));

    // valid key, valid out key blob, valid key size
    REQUIRE_NOTHROW(::gosling_ed25519_private_key_from_keyblob(out(privateKey), keyBlob.c_str(), keyBlob.size(), throw_on_error()));
    REQUIRE(privateKey.get() != nullptr);
    REQUIRE_NOTHROW(::gosling_ed25519_private_key_to_keyblob(privateKey.get(), keyBlobRaw, ED25519_KEYBLOB_SIZE, throw_on_error()));
    REQUIRE(std::string(keyBlobRaw) == keyBlob);
}

TEST_CASE("gosling_ed25519_public_key_from_ed25519_private_key") {
    unique_ptr<gosling_ed25519_public_key> publicKey;
    unique_ptr<gosling_ed25519_private_key> privateKey;

    // no valid inputs
    REQUIRE_THROWS(::gosling_ed25519_public_key_from_ed25519_private_key(nullptr, nullptr, throw_on_error()));

    // valid public key, invalid private key

    // invalid public key, valid private key

    // valid public key, valid private key

    REQUIRE(!"Incomplete Test without public key setter to compare with");
}

TEST_CASE("gosling_string_is_valid_v3_onion_service_id") {

    const char validServiceId[] = "6l62fw7tqctlu5fesdqukvpoxezkaxbzllrafa2ve6ewuhzphxczsjyd";
    const char invalidServiceId[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    REQUIRE(sizeof(validServiceId) == sizeof(invalidServiceId));
    REQUIRE(sizeof(validServiceId) == V3_ONION_SERVICE_ID_SIZE);

    // no valid inputs
    REQUIRE_THROWS(::gosling_string_is_valid_v3_onion_service_id(nullptr, 0, throw_on_error()));
    REQUIRE_THROWS(::gosling_string_is_valid_v3_onion_service_id(nullptr, 1, throw_on_error()));
    REQUIRE_THROWS(::gosling_string_is_valid_v3_onion_service_id(nullptr, V3_ONION_SERVICE_ID_SIZE, throw_on_error()));

    // valid service id, invalid lengths
    REQUIRE_THROWS(::gosling_string_is_valid_v3_onion_service_id(validServiceId, 0, throw_on_error()));
    REQUIRE_THROWS(::gosling_string_is_valid_v3_onion_service_id(validServiceId, 1, throw_on_error()));
    REQUIRE_THROWS(::gosling_string_is_valid_v3_onion_service_id(validServiceId, V3_ONION_SERVICE_ID_SIZE, throw_on_error()));

    // valid service id, valid length
    REQUIRE(::gosling_string_is_valid_v3_onion_service_id(validServiceId, V3_ONION_SERVICE_ID_LENGTH, throw_on_error()));

    // invalid service id, valid lenth
    REQUIRE_THROWS(::gosling_string_is_valid_v3_onion_service_id(nullptr, V3_ONION_SERVICE_ID_LENGTH, throw_on_error()));
    REQUIRE_FALSE(::gosling_string_is_valid_v3_onion_service_id(invalidServiceId, V3_ONION_SERVICE_ID_LENGTH, throw_on_error()));
}

#pragma once

#include <string>
#include <cstdint>

namespace margelo::nitro::metamask_nativeutils {

/**
 * Validate if a character is a valid hexadecimal character
 * @param c Character to validate
 * @return true if character is valid hex (0-9, A-F, a-f)
 */
bool isValidHexChar(char c);

/**
 * Validate hex string format (even length, valid hex characters)
 * @param hex Hex string to validate
 * @throws std::runtime_error if hex string is invalid
 */
void validateHexString(const std::string& hex);

/**
 * Convert single hex character to byte value
 * @param c Hex character to convert
 * @return Byte value (0-15)
 * @throws std::runtime_error if character is invalid
 */
uint8_t hexCharToByte(char c);

/**
 * Convert hex string to bytes with validation
 * @param hex Hex string to convert
 * @param bytes Output buffer for bytes
 * @param expectedLen Expected length in bytes
 * @throws std::runtime_error if hex string is invalid or wrong length
 */
void hexToBytes(const std::string& hex, uint8_t* bytes, size_t expectedLen);

} // namespace margelo::nitro::metamask_nativeutils

#include "SHA3.h"
#include <fstream>
#include <stdexcept>

SHA3::SHA3(int bitLength) : bitLength(bitLength) {
    initializeState();
}

void SHA3::initializeState() {
    for (size_t i = 0; i < STATE_SIZE; ++i) {
        state[i] = 0;
    }
}

std::vector<unsigned char> SHA3::pad(const std::vector<unsigned char>& data) {
    // Simple padding for demonstration.
    std::vector<unsigned char> padded = data;
    padded.push_back(0x06); // Padding starts with 0x06
    while (padded.size() % (SHA3_256_DIGEST_SIZE * 2) != 0) {
        padded.push_back(0x00);
    }
    padded.back() |= 0x80; // Pad with 0x80 at the end
    return padded;
}

void SHA3::absorb(const std::vector<unsigned char>& data) {
    std::vector<unsigned char> padded = pad(data);
    // Simplified absorption logic: example only
    for (size_t i = 0; i < padded.size(); i += 8) {
        unsigned long long part = 0;
        for (size_t j = 0; j < 8; j++) {
            part |= static_cast<unsigned long long>(padded[i + j]) << (8 * j);
        }
        state[i / 8 % STATE_SIZE] ^= part;
        keccakF1600StatePermutation();
    }
}

void SHA3::keccakF1600StatePermutation() {
    // This function should perform the actual Keccak permutation.
    // Placeholder for the permutation rounds.
}

std::vector<unsigned char> SHA3::squeeze() {
    // Extracting the digest from the state
    std::vector<unsigned char> digest(SHA3_256_DIGEST_SIZE);
    for (size_t i = 0; i < digest.size(); ++i) {
        digest[i] = state[i / 8] >> (8 * (i % 8)) & 0xFF;
    }
    return digest;
}

std::string SHA3::hash(const std::vector<unsigned char>& data) {
    absorb(data);
    std::vector<unsigned char> result = squeeze();
    std::string hexHash;
    for (unsigned char c : result) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", c);
        hexHash += buf;
    }
    return hexHash;
}

std::string SHA3::hashFile(const std::string& filePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        throw std::runtime_error("Cannot open file.");
    }

    std::vector<unsigned char> data((std::istreambuf_iterator<char>(file)),
                                    std::istreambuf_iterator<char>());
    file.close();

    return hash(data);
}

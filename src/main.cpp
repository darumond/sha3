#include <cstdint>
#include <cstring>
#include <cstdio>
#include <iostream>
#include <fstream>
#include <vector>
#include <csignal>

class SHA3 {
public:
	// Constructor: Initializes the SHA3 context with the desired hash bit length
	SHA3(int hashBitLength) {
		memset(state, 0, sizeof(state));
		memset(stateBytes, 0, sizeof(stateBytes)); // Initialize stateBytes to zero
		position = 0;

		switch (hashBitLength) {
			case 224:
				rateSize = 144; // 200 - 2 * outputLength (outputLength = 28 bytes)
				outputLength = 28;
				break;
			case 256:
				rateSize = 136; // 200 - 2 * outputLength (outputLength = 32 bytes)
				outputLength = 32;
				break;
			case 384:
				rateSize = 104; // 200 - 2 * outputLength (outputLength = 48 bytes)
				outputLength = 48;
				break;
			case 512:
				rateSize = 72;  // 200 - 2 * outputLength (outputLength = 64 bytes)
				outputLength = 64;
				break;
			default:
				// Default to SHA3-256
				rateSize = 136;
				outputLength = 32;
				break;
		}
	}

	// Updates the SHA3 context with new data
	void absorb(const uint8_t* input, size_t length) {
		size_t i;
		size_t currentPosition = position;

		for (i = 0; i < length; i++) {
			stateBytes[currentPosition++] ^= input[i];
			if (currentPosition >= rateSize) {
				keccakF();
				currentPosition = 0;
			}
		}
		position = currentPosition;
	}

	// Finalizes the hash and outputs the digest
	void squeeze(uint8_t* digest) {
		stateBytes[position] ^= 0x06;            // SHA-3 padding (0x06 is the SHA-3 domain separator)
		stateBytes[rateSize - 1] ^= 0x80;      // Final bit padding

		keccakF();                 // Perform the final permutation

		// Copy the hash output from stateBytes to the provided digest buffer
		memcpy(digest, stateBytes, outputLength);
	}

	// Returns the message digest length
	size_t getOutputLength() const {
		return outputLength;
	}

private:
	uint64_t state[25];    // State array as 64-bit words
	uint8_t stateBytes[200];   // State array as bytes
	size_t position;         // Position tracker
	size_t rateSize;       // Rate size
	size_t outputLength;      // Message digest length

	// Keccak-f[1600] permutation
	void keccakF() {
		static const uint64_t roundConstants[24] = {
				0x0000000000000001ULL, 0x0000000000008082ULL,
				0x800000000000808aULL, 0x8000000080008000ULL,
				0x000000000000808bULL, 0x0000000080000001ULL,
				0x8000000080008081ULL, 0x8000000000008009ULL,
				0x000000000000008aULL, 0x0000000000000088ULL,
				0x0000000080008009ULL, 0x000000008000000aULL,
				0x000000008000808bULL, 0x800000000000008bULL,
				0x8000000000008089ULL, 0x8000000000008003ULL,
				0x8000000000008002ULL, 0x8000000000000080ULL,
				0x000000000000800aULL, 0x800000008000000aULL,
				0x8000000080008081ULL, 0x8000000000008080ULL,
				0x0000000080000001ULL, 0x8000000080008008ULL
		};

		uint64_t lanes[25];
		uint64_t temp, columnParity[5];

		// Convert state from bytes to 64-bit words (little-endian)
		for (int i = 0; i < 25; i++) {
			lanes[i] = 0;
			for (int j = 0; j < 8; j++) {
				lanes[i] |= (uint64_t)stateBytes[i * 8 + j] << (8 * j);
			}
		}

		// 24 rounds of the permutation
		for (int round = 0; round < 24; round++) {
			// θ step
			for (int i = 0; i < 5; i++) {
				columnParity[i] = lanes[i] ^ lanes[i + 5] ^ lanes[i + 10] ^ lanes[i + 15] ^ lanes[i + 20];
			}
			for (int i = 0; i < 5; i++) {
				temp = ROTL64(columnParity[(i + 1) % 5], 1) ^ columnParity[(i + 4) % 5];
				for (int j = 0; j < 25; j += 5) {
					lanes[j + i] ^= temp;
				}
			}

			// ρ and π steps
			temp = lanes[1];
			for (int i = 0; i < 24; i++) {
				int targetLane = KeccakPi[i];
				columnParity[0] = lanes[targetLane];
				lanes[targetLane] = ROTL64(temp, KeccakRhoOffsets[i]);
				temp = columnParity[0];
			}

			// χ step
			for (int j = 0; j < 25; j += 5) {
				uint64_t row[5];
				for (int i = 0; i < 5; i++) {
					row[i] = lanes[j + i];
				}
				for (int i = 0; i < 5; i++) {
					lanes[j + i] ^= (~row[(i + 1) % 5]) & row[(i + 2) % 5];
				}
			}

			// ι step
			lanes[0] ^= roundConstants[round];
		}

		// Convert state back to bytes (little-endian)
		for (int i = 0; i < 25; i++) {
			for (int j = 0; j < 8; j++) {
				stateBytes[i * 8 + j] = (lanes[i] >> (8 * j)) & 0xFF;
			}
		}
	}

	// Rotate left operation for 64-bit integers
	inline uint64_t ROTL64(uint64_t x, int shift) {
		return (x << shift) | (x >> (64 - shift));
	}

	// π step constants
	static const int KeccakPi[24];
	// ρ step constants
	static const int KeccakRhoOffsets[24];
};

// π step constants
const int SHA3::KeccakPi[24] = {
		10, 7, 11, 17, 18,
		3, 5, 16, 8, 21,
		24, 4, 15, 23, 19,
		13, 12, 2, 20, 14,
		22, 9, 6, 1
};

// ρ step constants
const int SHA3::KeccakRhoOffsets[24] = {
		1, 3, 6, 10, 15,
		21, 28, 36, 45, 55,
		2, 14, 27, 41, 56,
		8, 25, 43, 62, 18,
		39, 61, 20, 44
};

// Helper function to read file contents into a vector
bool readFile(const std::string& filePath, std::vector<uint8_t>& data) {
	std::ifstream file(filePath);
	if (!file) {
		return false;
	}

	data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
	return true;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <file_path>\n";
		return 1;
	}

	std::cout << "Welcome to our SHA3 Tool!" << '\n';

	std::vector<uint8_t> data;
	if (!readFile(argv[1], data)) {
		std::cerr << "Error: Failed to open file: " << argv[1] << "\n";
		return 1;
	}

	int hashBitLengths[4] = {224, 256, 384, 512};
	uint8_t hash[64];

	for (int i = 0; i < 4; i++) {
		SHA3 sha3(hashBitLengths[i]);
		sha3.absorb(data.data(), data.size());
		sha3.squeeze(hash);

		std::cout << "\nSHA3-" << hashBitLengths[i] << " Hash:\n";
		for (size_t j = 0; j < sha3.getOutputLength(); j++) {
			printf("%02x", hash[j]);
		}
		std::cout << std::endl;
	}
	return 0;
}


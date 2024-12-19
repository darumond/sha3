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
	SHA3(int bitlen) {
		memset(s, 0, sizeof(s));
		memset(sb, 0, sizeof(sb)); // Initialize sb to zero
		pt = 0;

		switch (bitlen) {
			case 224:
				rsiz = 144; // 200 - 2 * mdlen (mdlen = 28 bytes)
				mdlen = 28;
				break;
			case 256:
				rsiz = 136; // 200 - 2 * mdlen (mdlen = 32 bytes)
				mdlen = 32;
				break;
			case 384:
				rsiz = 104; // 200 - 2 * mdlen (mdlen = 48 bytes)
				mdlen = 48;
				break;
			case 512:
				rsiz = 72;  // 200 - 2 * mdlen (mdlen = 64 bytes)
				mdlen = 64;
				break;
			default:
				// Default to SHA3-256
				rsiz = 136;
				mdlen = 32;
				break;
		}
	}

	// Updates the SHA3 context with new data
	void update(const uint8_t* data, size_t len) {
		size_t i;
		size_t j = pt;

		for (i = 0; i < len; i++) {
			sb[j++] ^= data[i];
			if (j >= rsiz) {
				keccakF();
				j = 0;
			}
		}
		pt = j;
	}

	// Finalizes the hash and outputs the digest
	void finalize(uint8_t* hash) {
		sb[pt] ^= 0x06;            // SHA-3 padding (0x06 is the SHA-3 domain separator)
		sb[rsiz - 1] ^= 0x80;      // Final bit padding

		keccakF();                 // Perform the final permutation

		// Copy the hash output from sb to the provided hash buffer
		memcpy(hash, sb, mdlen);
	}

	// Returns the message digest length
	size_t getHashLength() const {
		return mdlen;
	}

private:
	uint64_t s[25];    // State array as 64-bit words
	uint8_t sb[200];   // State array as bytes
	size_t pt;         // Position tracker
	size_t rsiz;       // Rate size
	size_t mdlen;      // Message digest length

	// Keccak-f[1600] permutation
	void keccakF() {
		static const uint64_t RC[24] = {
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

		uint64_t st[25];
		uint64_t t, bc[5];

		// Convert state from bytes to 64-bit words (little-endian)
		for (int i = 0; i < 25; i++) {
			st[i] = 0;
			for (int j = 0; j < 8; j++) {
				st[i] |= (uint64_t)sb[i * 8 + j] << (8 * j);
			}
		}

		// 24 rounds of the permutation
		for (int round = 0; round < 24; round++) {
			// θ step
			for (int i = 0; i < 5; i++) {
				bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^ st[i + 15] ^ st[i + 20];
			}
			for (int i = 0; i < 5; i++) {
				t = ROTL64(bc[(i + 1) % 5], 1) ^ bc[(i + 4) % 5];
				for (int j = 0; j < 25; j += 5) {
					st[j + i] ^= t;
				}
			}

			// ρ and π steps
			t = st[1];
			for (int i = 0; i < 24; i++) {
				int j = KeccakP1600PiLane[i];
				bc[0] = st[j];
				st[j] = ROTL64(t, KeccakP1600RhoOffsets[i]);
				t = bc[0];
			}

			// χ step
			for (int j = 0; j < 25; j += 5) {
				uint64_t temp[5];
				for (int i = 0; i < 5; i++) {
					temp[i] = st[j + i];
				}
				for (int i = 0; i < 5; i++) {
					st[j + i] ^= (~temp[(i + 1) % 5]) & temp[(i + 2) % 5];
				}
			}

			// ι step
			st[0] ^= RC[round];
		}

		// Convert state back to bytes (little-endian)
		for (int i = 0; i < 25; i++) {
			for (int j = 0; j < 8; j++) {
				sb[i * 8 + j] = (st[i] >> (8 * j)) & 0xFF;
			}
		}
	}

	// Rotate left operation for 64-bit integers
	inline uint64_t ROTL64(uint64_t x, int y) {
		return (x << y) | (x >> (64 - y));
	}

	// π step constants
	static const int KeccakP1600PiLane[24];
	// ρ step constants
	static const int KeccakP1600RhoOffsets[24];
};

// π step constants
const int SHA3::KeccakP1600PiLane[24] = {
		10, 7, 11, 17, 18,
		3, 5, 16, 8, 21,
		24, 4, 15, 23, 19,
		13, 12, 2, 20, 14,
		22, 9, 6, 1
};

// ρ step constants
const int SHA3::KeccakP1600RhoOffsets[24] = {
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

// Main function
int main() {
	int hashBitLength = 0;
	int choice = 0;
	std::string input;

	// Choose SHA-3 variant
	std::cout << "Select SHA-3 variant:\n";
	std::cout << "1. SHA3-224\n";
	std::cout << "2. SHA3-256\n";
	std::cout << "3. SHA3-384\n";
	std::cout << "4. SHA3-512\n";
	std::cout << "Enter choice (1-4): ";
	std::cin >> choice;

	switch (choice) {
		case 1:
			hashBitLength = 224;
			break;
		case 2:
			hashBitLength = 256;
			break;
		case 3:
			hashBitLength = 384;
			break;
		case 4:
			hashBitLength = 512;
			break;
		default:
			std::cout << "Invalid choice. Defaulting to SHA3-256.\n";
			hashBitLength = 256;
			break;
	}

	// Choose to hash a phrase or a file
	std::cout << "\nDo you want to hash a phrase or a file?\n";
	std::cout << "1. Phrase\n";
	std::cout << "2. File\n";
	std::cout << "Enter choice (1-2): ";
	std::cin >> choice;
	std::cin.ignore(); // Clear the newline character from the input buffer

	std::vector<uint8_t> data;

	if (choice == 1) {
		// Hash a phrase
		std::cout << "\nEnter the phrase to hash: ";
		std::getline(std::cin, input);

		// Convert input string to a vector of bytes
		data.assign(input.begin(), input.end());
	} else if (choice == 2) {
		// Hash a file
		std::cout << "\nEnter the file path: ";
		std::getline(std::cin, input);

		if (!readFile(input, data)) {
			std::cerr << "Error: Failed to open or read the file.\n";
			return 1;
		}
	} else {
		std::cerr << "Invalid choice.\n";
		return 1;
	}

	// Initialize SHA-3 with the chosen bit length
	SHA3 sha3(hashBitLength);
	uint8_t hash[64]; // Maximum hash size is 64 bytes (512 bits)

	// Update the SHA-3 context with the data
	sha3.update(data.data(), data.size());
	// Finalize and get the hash
	sha3.finalize(hash);

	// Get the actual hash length
	size_t hashLength = sha3.getHashLength();

	// Print the hash in hexadecimal format
	std::cout << "\nSHA3-" << hashBitLength << " Hash:\n";
	for (size_t i = 0; i < hashLength; i++) {
		printf("%02x", hash[i]);
	}
	std::cout << std::endl;

	return 0;
}


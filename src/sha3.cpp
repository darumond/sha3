#include "sha3.h"
#include <cstring>

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

inline uint64_t SHA3::ROTL64(uint64_t x, int shift) {
	uint64_t result = x;
	for (int i = 0; i < shift; i++) {
		uint64_t msb = (result >> 63) & 1;
		result = (result << 1) | msb;
	}
	return result;
}

SHA3::SHA3(int hashBitLength) {
	memset(state, 0, sizeof(state));
	memset(stateBytes, 0, sizeof(stateBytes));
	position = 0;

	switch (hashBitLength) {
		case 224:
			rateSize = 144;
			outputLength = 28;
			break;
		case 256:
			rateSize = 136;
			outputLength = 32;
			break;
		case 384:
			rateSize = 104;
			outputLength = 48;
			break;
		case 512:
			rateSize = 72;
			outputLength = 64;
			break;
		default:
			rateSize = 136;
			outputLength = 32;
			break;
	}
}

void SHA3::absorb(const uint8_t* input, size_t length) {
	size_t currentPosition = position;
	for (size_t i = 0; i < length; i++) {
		stateBytes[currentPosition++] ^= input[i];
		if (currentPosition >= rateSize) {
			keccakF();
			currentPosition = 0;
		}
	}
	position = currentPosition;
}

void SHA3::squeeze(uint8_t* digest) {
	stateBytes[position] ^= 0x06;
	stateBytes[rateSize - 1] ^= 0x80;
	keccakF();
	memcpy(digest, stateBytes, outputLength);
}

size_t SHA3::getOutputLength() const {
	return outputLength;
}

void SHA3::keccakF() {
	uint64_t lanes[25], temp, columnParity[5];
	for (int i = 0; i < 25; i++) {
		lanes[i] = 0;
		for (int j = 0; j < 8; j++) {
			lanes[i] |= (uint64_t)stateBytes[i * 8 + j] << (8 * j);
		}
	}
	for (int round = 0; round < 24; round++) {
		for (int i = 0; i < 5; i++) {
			columnParity[i] = lanes[i] ^ lanes[i + 5] ^ lanes[i + 10] ^ lanes[i + 15] ^ lanes[i + 20];
		}
		for (int i = 0; i < 5; i++) {
			temp = ROTL64(columnParity[(i + 1) % 5], 1) ^ columnParity[(i + 4) % 5];
			for (int j = 0; j < 25; j += 5) {
				lanes[j + i] ^= temp;
			}
		}
		temp = lanes[1];
		for (int i = 0; i < 24; i++) {
			int targetLane = KeccakPi[i];
			columnParity[0] = lanes[targetLane];
			lanes[targetLane] = ROTL64(temp, KeccakRhoOffsets[i]);
			temp = columnParity[0];
		}
		for (int j = 0; j < 25; j += 5) {
			uint64_t row[5];
			for (int i = 0; i < 5; i++) {
				row[i] = lanes[j + i];
			}
			for (int i = 0; i < 5; i++) {
				lanes[j + i] ^= (~row[(i + 1) % 5]) & row[(i + 2) % 5];
			}
		}
		lanes[0] ^= roundConstants[round];
	}
	for (int i = 0; i < 25; i++) {
		for (int j = 0; j < 8; j++) {
			stateBytes[i * 8 + j] = (lanes[i] >> (8 * j)) & 0xFF;
		}
	}
}


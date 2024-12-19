#ifndef SHA3_H
#define SHA3_H

#include <cstdint>
#include <cstddef>

class SHA3 {
public:
	explicit SHA3(int hashBitLength);
	void absorb(const uint8_t* input, size_t length);
	void squeeze(uint8_t* digest);
	size_t getOutputLength() const;

private:
	uint64_t state[25];
	uint8_t stateBytes[200];
	size_t position;
	size_t rateSize;
	size_t outputLength;

	void keccakF();
	inline uint64_t ROTL64(uint64_t x, int shift);

	static const int KeccakPi[24];
	static const int KeccakRhoOffsets[24];
};

#endif // SHA3_H

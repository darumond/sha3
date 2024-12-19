#include "sha3.h"
#include "utils.h"
#include <iostream>
#include <vector>

int main(int argc, char* argv[]) {
	if (argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <file_path>\n";
		return 1;
	}

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

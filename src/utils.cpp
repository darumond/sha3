#include "utils.h"
#include <fstream>
#include <iterator>

bool readFile(const std::string& filePath, std::vector<uint8_t>& data) {
	std::ifstream file(filePath, std::ios::binary);
	if (!file) {
		return false;
	}
	data.assign(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
	return true;
}

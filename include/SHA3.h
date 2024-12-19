#ifndef SHA3_H
#define SHA3_H

#include <vector>
#include <string>

class SHA3 {
public:
    static const size_t SHA3_256_DIGEST_SIZE = 32;

    SHA3(int bitLength = 256);
    std::string hash(const std::vector<unsigned char>& data);
    std::string hashFile(const std::string& filePath);

private:
    static const size_t STATE_SIZE = 5 * 5; // Simplified to a flat array
    unsigned long long state[STATE_SIZE];
    int bitLength;

    void initializeState();
    void absorb(const std::vector<unsigned char>& data);
    std::vector<unsigned char> squeeze();
    void keccakF1600StatePermutation();
    std::vector<unsigned char> pad(const std::vector<unsigned char>& data);
};

#endif // SHA3_H

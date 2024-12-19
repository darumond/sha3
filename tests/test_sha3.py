import subprocess

BINARY = "./sha3"

TEST_FILE = "tests/fichier_50mo"

EXPECTED_HASHES = {
    224: "4652fff3cab0c1ed1fc141568c57aa6019f0457e42eb11d07587cdea",
    256: "b8022349107f1a86858600868d6d1ec38b8d3d1d17692fa935110c974f9846cb",
    384: "869185209dec85e86d412f376d5b837476faf1ee7145f840ae678e969459745653074d7e4abe786d672960db52a105dd",
    512: "fdd569c299cdb60bd3c3c6c7e5610f3bfd39001e494a4c2b61c6203fc689800f01e699eb6748ad829ac509d470687e2dd995b8b7d083fb86b262162c11ec35e6",
}

def run_sha3_tool(file_path):
    result = subprocess.run([BINARY, file_path], capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: Failed to run binary: {result.stderr}")
        exit(1)
    return result.stdout

def extract_hash(output, hashBitLength):
    lines = output.splitlines()
    for i in range(len(lines)):
        if f"SHA3-{hashBitLength} Hash:" in lines[i]:
            return lines[i + 1].strip()
    return None

def main():
    print("Running SHA3 Test Suite...")

    output = run_sha3_tool(TEST_FILE)
    print(output)

    for bit_length, expected in EXPECTED_HASHES.items():
        actual_hash = extract_hash(output, bit_length)
        if actual_hash == expected:
            print(f"SHA3-{bit_length} passed ✅")
        else:
            print(f"SHA3-{bit_length} failed ❌")
            print(f"Expected: {expected}")
            print(f"Got: {actual_hash}")

if __name__ == "__main__":
    main()

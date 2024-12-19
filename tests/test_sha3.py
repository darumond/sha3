import subprocess

BINARY = "./sha3"

TEST_FILE = "tests/test"

EXPECTED_HASHES = {
    224: "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
    256: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    384: "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
    512: "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
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

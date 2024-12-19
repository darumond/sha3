import subprocess
import time

BINARY = "./sha3"

TEST_FILES = {
    "tests/fichier_50mo": {
        224: "4652fff3cab0c1ed1fc141568c57aa6019f0457e42eb11d07587cdea",
        256: "b8022349107f1a86858600868d6d1ec38b8d3d1d17692fa935110c974f9846cb",
        384: "869185209dec85e86d412f376d5b837476faf1ee7145f840ae678e969459745653074d7e4abe786d672960db52a105dd",
        512: "fdd569c299cdb60bd3c3c6c7e5610f3bfd39001e494a4c2b61c6203fc689800f01e699eb6748ad829ac509d470687e2dd995b8b7d083fb86b262162c11ec35e6",
    },
    "tests/fichier_abc": {
        224: "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
        256: "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
        384: "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
        512: "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
    },
}

def run_sha3_tool(file_path):
    start_time = time.time()  # Démarre le timer
    result = subprocess.run([BINARY, file_path], capture_output=True, text=True)
    end_time = time.time()  # Arrête le timer
    duration = end_time - start_time

    if result.returncode != 0:
        print(f"Error: Failed to run binary on {file_path}: {result.stderr}")
        exit(1)

    return result.stdout, duration

def extract_hash(output, hashBitLength):
    lines = output.splitlines()
    for i in range(len(lines)):
        if f"SHA3-{hashBitLength} Hash:" in lines[i]:
            return lines[i + 1].strip()
    return None

def main():
    print("Running SHA3 Test Suite on Multiple Files...\n")

    for test_file, expected_hashes in TEST_FILES.items():
        print(f"Testing file: {test_file}")

        output, duration = run_sha3_tool(test_file)
        print(output)
        print(f"Execution time for {test_file}: {duration:.4f} seconds\n")

        for bit_length, expected in expected_hashes.items():
            actual_hash = extract_hash(output, bit_length)

            if actual_hash == expected:
                print(f"SHA3-{bit_length} passed ✅")
            else:
                print(f"SHA3-{bit_length} failed ❌")
                print(f"Expected: {expected}")
                print(f"Got: {actual_hash}")
        print("-" * 50)

if __name__ == "__main__":
    main()

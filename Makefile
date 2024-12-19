CXX = g++

CXXFLAGS = -std=c++17 -Wall -Wextra -O2

TARGET = sha3

SRC = src/main.cpp src/sha3.cpp src/utils.cpp
INCLUDE = -Iinclude

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) $(INCLUDE) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

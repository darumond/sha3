CXX = g++

CXXFLAGS = -std=c++17 -Wall -Wextra -O2

TARGET = sha3

SRC = src/main.cpp

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)


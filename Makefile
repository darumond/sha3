CXX = g++
CXXFLAGS = -std=c++11 -Wall -Iinclude

SRCS = src/main.cpp
OBJS = $(SRCS:.cpp=.o)
EXEC = sha3_hash

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

clean:
	rm -f $(OBJS) $(EXEC)

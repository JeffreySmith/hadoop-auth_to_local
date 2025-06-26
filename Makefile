CXX = clang++
#CXX = /opt/homebrew/bin/gcc-15
CXXFLAGS = -std=c++17 -g -ggdb -Wall -Wextra -O0 -MMD -MP -Iinclude -fsanitize=address,undefined -I/opt/homebrew/include -I/opt/homebrew/include/boost
-include $(OBJS:.o=.d)
SRCS = $(wildcard src/*.cc)

OBJS = $(patsubst src/%.cc, build/%.o, $(SRCS))
DEPS = $(OBJS:.o=.d)
TARGET = main

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CXX) $(CXXFLAGS) -o $@ $^

build/%.o: src/%.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -rf main build/* $(TARGET)


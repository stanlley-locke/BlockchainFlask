CXX       = g++
CXXFLAGS  = -std=c++17 -Wall -Wextra
QT_CFLAGS = $(shell pkg-config --cflags Qt5Widgets Qt5Core Qt5Gui)
QT_LIBS   = $(shell pkg-config --libs   Qt5Widgets Qt5Core Qt5Gui)
MOC       = moc

TARGET       = learning_platform
SOURCES      = main.cpp
OBJECTS      = $(SOURCES:.cpp=.o)
MOC_SOURCES  = main.moc

.PHONY: all clean debug

all: $(MOC_SOURCES) $(TARGET)

$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $(TARGET) $(QT_LIBS)

# compile with -fPIC plus your other flags
main.o: main.cpp main.moc
	$(CXX) -fPIC $(CXXFLAGS) $(QT_CFLAGS) -c main.cpp -o main.o

# generate meta‑object code
main.moc: main.cpp
	$(MOC) main.cpp -o main.moc

clean:
	rm -f $(OBJECTS) $(TARGET) $(MOC_SOURCES) temp_code.cpp temp_program

# build with debug symbols
debug: CXXFLAGS += -g -O0
debug: all

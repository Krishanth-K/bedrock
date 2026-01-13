BUILD_DIR := build
TARGET    := $(BUILD_DIR)/mem_alloc

.PHONY: all configure build run clean rebuild

all: run

configure:
	mkdir -p $(BUILD_DIR)
	cd $(BUILD_DIR) && cmake ..

build: configure
	cd $(BUILD_DIR) && cmake --build .

run: build
	clear && $(TARGET)

runnoc: build
	$(TARGET)

clean:
	rm -rf $(BUILD_DIR)

rebuild: clean all



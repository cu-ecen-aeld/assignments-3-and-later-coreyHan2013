SRC := writer.c
TARGET = writer
CROSS_COMPILE :=
CC=${CROSS_COMPILE}gcc
CFLAGS := -g -Wall

all: $(TARGET)

$(TARGET) : $(SRC)
	$(CROSS_COMPILE)gcc $(CFLAGS) -o $(TARGET) $^

clean:
	-rm -f *.o $(TARGET)

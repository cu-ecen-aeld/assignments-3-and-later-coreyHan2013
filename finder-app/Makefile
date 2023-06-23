TARGET		 = writer
CROSS_COMPILE	?=
CC		 =$(CROSS_COMPILE)gcc
CFLAGS		:= -g -Wall
SRC		:= writer.c

all: $(TARGET)

$(TARGET) : $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $^

clean:
	-rm -f *.o $(TARGET)

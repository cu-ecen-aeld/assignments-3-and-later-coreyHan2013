TARGET		?= aesdsocket
CC		?= $(CROSS_COMPILE)gcc
CFLAGS		?= -g -Wall -Werror
SRC		= aesdsocket.c
LDFLAGS         ?= -lpthread -lrt

all: $(TARGET)

$(TARGET) : $(SRC)
	$(CC) $(CFLAGS) $^ -o $(TARGET) $(LDFLAGS)

clean:
	-rm -f *.o $(TARGET)

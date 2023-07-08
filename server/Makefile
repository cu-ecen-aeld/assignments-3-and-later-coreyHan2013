TARGET		 = aesdsocket
CROSS_COMPILE	?=
CC		 =$(CROSS_COMPILE)gcc
CFLAGS		:= -g -Wall -Werror
SRC		:= aesdsocket.c

all: $(TARGET)

$(TARGET) : $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $^

clean:
	-rm -f *.o $(TARGET)

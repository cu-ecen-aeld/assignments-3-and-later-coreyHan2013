TARGET		?= aesdsocket
CC		?= $(CROSS_COMPILE)gcc
CFLAGS		?= -g -Wall -Werror
SRC		= aesdsocket.c
LDFLAGS         ?= -lpthread -lrt
USE_AESD_CHAR_DEVICE ?= 1


ifeq ($(USE_AESD_CHAR_DEVICE),1)
	CFLAGS += -DUSE_AESD_CHAR_DEVICE
endif

all: $(TARGET)

$(TARGET) : $(SRC)
	$(CC) $(CFLAGS) $^ -o $(TARGET) $(LDFLAGS)

clean:
	-rm -f *.o $(TARGET)

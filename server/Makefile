TARGET		?= aesdsocket
CC		?= $(CROSS_COMPILE)gcc
CFLAGS		?= -g -Wall -Werror
SRC		= aesdsocket.c
LDFLAGS         ?= -lpthread -lrt
CEXTRAFLAGS     =
USE_AESD_CHAR_DEVICE = 1


ifeq ($(USE_AESD_CHAR_DEVICE),1)
	CEXTRAFLAGS += -DUSE_AESD_CHAR_DEVICE
endif

all: $(TARGET)

$(TARGET) : $(SRC)
	$(CC) $(CFLAGS) $(CEXTRAFLAGS) $^ -o $(TARGET) $(LDFLAGS)

clean:
	-rm -f *.o $(TARGET)

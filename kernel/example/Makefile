TARGET = pcapsend
LIBS = -lm
CC = gcc
PWD?=$(shell pwd)
M:=$(PWD)
CFLAGS = -Wall -I$(M)/../include 
ifneq (,$(QUICK_TX_DEBUG))
CFLAGS += -g -O0 -DHAVE_QUICK_TX_DEBUG
endif

.PHONY: default all clean

default: $(TARGET)
all: default

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -Wall $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)

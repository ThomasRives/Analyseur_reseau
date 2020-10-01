CC ?=	gcc
CFLAGS ?=	-Wall -Wextra -Werror -g
LDLIBS ?= -lm -lpcap
INCLUDE_PATH = ./include
TARGET   =	main
SRCDIR   =	src
OBJDIR   =	obj
BINDIR   =	bin
SOURCES  :=	$(wildcard $(SRCDIR)/*.c)
INCLUDES :=	$(wildcard $(INCLUDE_PATH)/*.h)
OBJECTS  :=	$(SOURCES:$(SRCDIR)/%.c=$(OBJDIR)/%.o)


$(BINDIR)/$(TARGET): $(OBJECTS)
	mkdir -p $(BINDIR)
	$(CC) -o $@ $^ $(CFLAGS) $(LDLIBS)
	@echo "Linking complete!"
$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	mkdir -p $(OBJDIR)
	$(CC) -o $@ -c $< $(CFLAGS) -I$(INCLUDE_PATH)


obj/test.o: src/test.c
	$(CC) -o $@ -c $< $(CFLAGS) -I$(INCLUDE_PATH)


.PHONY: clean test
clean:
	rm -rf obj/*.o
	rm -f bin/main

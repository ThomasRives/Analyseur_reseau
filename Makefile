CC ?= gcc
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
LIBS :=

# Update include path
INCLUDE_PATH := $(INCLUDE_PATH) $(foreach lib_path, $(LIBS), ./$(lib_path))
INCLUDE := $(foreach lib_dir, $(INCLUDE_PATH), $(addprefix -I, $(lib_dir)))

# .o files of the library
LIB_OBJ := $(foreach lib_obj, $(LIBS), $(OBJDIR)/$(lib_obj).o)

# compile all the librairies
$(foreach lib, $(LIBS), $(shell $(CC) -o $(OBJDIR)/$(lib).o -c $(lib)/$(lib).c $(CFLAGS)))

$(BINDIR)/$(TARGET): $(OBJECTS)
	mkdir -p $(BINDIR)
	$(CC) -o $@ $^ $(CFLAGS) $(LDLIBS)
	@echo "Linking complete!"
$(OBJECTS): $(OBJDIR)/%.o : $(SRCDIR)/%.c
	mkdir -p $(OBJDIR)
	$(CC) -o $@ -c $< $(CFLAGS) -I$(INCLUDE_PATH)


obj/test.o: src/test.c
	$(CC) -o $@ -c $< $(CFLAGS) -I$(INCLUDE_PATH)

test:
	@make clean 1>/dev/null
	@make 1>/dev/null
	@valgrind -q --leak-check=full ./bin/main -i any -v 1 -o pcap_files/sctp.cap

.PHONY: clean test
clean:
	rm -rf obj/*.o
	rm -f bin/main

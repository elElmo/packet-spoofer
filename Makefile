BUILDROOT=build
OBJROOT=obj
OBJS=$(addprefix $(OBJDIR)/,spoofer.o)
CC=gcc
DEBUG=1
CFLAGS := -I./include -Wall -Werror -DDEBUG=$(DEBUG) -std=gnu99
BIN=spoofer

all: clean build

build: $(OBJS)
	@test -d $(BUILDROOT) || mkdir $(BUILDROOT)
	$(CC) $(OBJROOT)/*.o -o $(BUILDROOT)/$(BIN)

$(OBJDIR)/%.o: src/%.c
	@test -d $(OBJROOT) || mkdir $(OBJROOT)
	$(CC) $(CFLAGS) -c -o $(OBJROOT)$@ $<

$(OBJS): | $(OBJDIR)

clean: 
	rm -rf $(BUILDROOT) $(OBJROOT)

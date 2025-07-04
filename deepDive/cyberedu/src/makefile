GLIBCDIR = /usr
TARGET = ./bin/deepDive
LIBC:=/lib64/ld-linux-x86-64.so.2
OBJ = $(TARGET).o
CC = gcc
CFLAGS = -g
LINKGLIBCDIR = ./bin
DL:=$(LINKGLIBCDIR)/lib/ld-linux-x86-64.so.2
LDFLAGS = -nostdlib -nostartfiles -no-pie -fstack-protector \
	-B$(LINKGLIBCDIR)/ \
	-L.$(LINKGLIBCDIR)/lib/ \
	-I.$(GLIBCDIR)/include \
	-Wl,-rpath=$(LINKGLIBCDIR)/lib,-z,now,--dynamic-linker,$(DL)
STARTFILES = $(GLIBCDIR)/lib/crt1.o $(GLIBCDIR)/lib/crti.o `gcc --print-file-name=crtbegin.o`
ENDFILES = `gcc --print-file-name=crtend.o` $(GLIBCDIR)/lib/crtn.o
LIBGROUP = -Wl,--start-group $(LINKGLIBCDIR)/lib/libc.so.6 -lgcc -lgcc_eh -Wl,--end-group

.PHONY: all
all: 
	$(MAKE) obj
	# the incantation for doing a dynamic link with custom libc
	$(CC) $(LDFLAGS) -o $(TARGET) $(STARTFILES) $(OBJ) $(LIBGROUP) $(ENDFILES) 
	$(MAKE) libcsym
	rm $(OBJ)

obj:
	$(CC) $(CFLAGS) -c ./deepDive.c -o $(OBJ)

libcsym:
	objdump -M intel -d $(TARGET) > doc/deepDive.objdump
	readelf -a --wide $(TARGET) > doc/deepDive.re

	objdump -M intel -d $(GLIBCDIR)/lib/libc.so.6 > doc/libc.objdump
	readelf -a --wide $(GLIBCDIR)/lib/libc.so.6 > doc/libc.re

#
# I ended up not doing these as I think that simply blocking dynelf usage is enough. We don't have to torture 
# the ones that try to use it
#
# objcopy --rename-section '.dynamic'='.certainly-not-dynamic-section' ./bin/test

# cp /lib/x86_64-linux-gnu/libc.so.6 ./bin/system.libc
# objcopy --dump-section '.note.gnu.build-id'=./bin/fake-build-id ./bin/system.libc
# objcopy --update-section '.note.gnu.build-id'=./bin/fake-build-id $(GLIBCDIR)/lib/libc.so.6

# jank method to trick dynelf into giving wrong offsets
# cp $(GLIBCDIR)/lib/libc.so.6 ./bin/testlibc
# dd if=./bin/fake-build-id of=./bin/testlibc seek=$((0x370)) conv=notrunc bs=1
# cp ./bin/testlibc $(GLIBCDIR)/lib/libc.so.6
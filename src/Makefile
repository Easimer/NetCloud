CXXFLAGS=-fsanitize=address -g
OBJECTS=ncsrv.o stdio_nc.o hmac.o handle_fileread.o handle_filewrite.o handle_fileexists.o handle_filesize.o user_auth.o

all: ncsrv

ncsrv: $(OBJECTS)
	$(CXX) -o ncsrv $(OBJECTS) -lasan -lssl -lcrypto -lsqlite3

clean:
	rm -f ncsrv $(OBJECTS)

.PHONY: clean

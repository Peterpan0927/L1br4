all:
	clang exp.c librop/librop.c -framework IOKit -o pwn
clean:
	rm -rf pwn

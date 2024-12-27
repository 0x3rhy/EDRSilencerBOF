Main := EDRSilencer
CC_x64 := x86_64-w64-mingw32-gcc
CC_x64strip := x86_64-w64-mingw32-strip
CFLAGS = -s -w -Os -static -lfwpuclnt

all:
	$(CC_x64) $(CFLAGS) $(Main).c utils.c -o $(Main).x64.exe
all: tcp-block
	
tcp-block: main.o
	g++ -o tcp-block main.o -lpcap -lnet

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -r tcp-block *.o

all: tcp_block

tcp_block : main.o
	g++ -g -o tcp_block main.cpp -lpcap

main.o: 
	g++ -g -c -o main.o main.cpp


clean: 
	rm tcp_block
	rm -f *.o

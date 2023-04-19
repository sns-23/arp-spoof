CXXFLAGS = -Wall
LDLIBS = -lpcap

all: arp-spoof

main.o: mac.h ip.h ethhdr.h arphdr.h main.cpp

attack.o: mac.h ip.h ethhdr.h arphdr.h iphdr.h attack.cpp

arphdr.o: mac.h ip.h arphdr.h arphdr.cpp

ethhdr.o: mac.h ethhdr.h ethhdr.cpp

iphdr.o: ip.h iphdr.h iphdr.cpp

ip.o: ip.h ip.cpp

mac.o : mac.h mac.cpp

util.o: util.h util.cpp

arp-spoof: main.o arphdr.o ethhdr.o iphdr.o ip.o mac.o attack.o util.o
	$(LINK.cc) $^ $(CXXFLAGS) $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f arp-spoof *.o

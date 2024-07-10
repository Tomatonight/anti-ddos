PKGCONF = pkg-config
APP=build/anti_syn
SRCS-y=main.cpp anti.cpp
CXX=g++
CFLAGS += -O3 $(shell $(PKGCONF) --cflags libdpdk)
LDFLAGS += $(shell $(PKGCONF) --libs libdpdk)
$(APP):$(SRCS-y) anti.h
	$(CXX) $(CFLAGS) $(SRCS-y) -o $@ $(LDFLAGS)

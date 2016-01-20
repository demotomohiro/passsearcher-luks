#Copyright 2016 Tomohiro Matsumoto
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.

TESTPROG := hashtest
PROGNAME := passsearcher-luks

buildtype := release
#profiling := true

CC := gcc
CXX := g++
NVCC := nvcc

CFLAGS := -Wall -Wextra -D_GNU_SOURCE -include libcryptsetup/config.h
CCFLAGS := -std=c++11 -Wall -Wextra
NVCCFLAGS := -std c++11
TMPDIR := tmp
LDFLAGS := 
ifeq ($(buildtype),release)
	CFLAGS += -O2 -ffunction-sections -fdata-sections
	CCFLAGS += -O2
	NVCCFLAGS += 
	TMPDIR := tmp_release
ifdef profiling
	CFLAGS += -pg
	CCFLAGS += -pg
	NVCCFLAGS += -pg
	LDFLAGS += -pg
endif
else ifeq ($(buildtype),debug)
	CFLAGS += -O0 -g -ffunction-sections -fdata-sections
	CCFLAGS += -O0 -g
	NVCCFLAGS += -g -G
	TESTPROG := $(TESTPROG)d
	PROGNAME := $(PROGNAME)d
	TMPDIR := tmp_debug
else
	$(error buildtype must be release or debug)
endif

COMMON_CCFILES := sha1Block.cpp
COMMON_CUFILES := hmacSha1Cuda.cu mdCuda.cu
TESTPROG_CCFILES := hashtest.cpp hmac.cpp gcryptMD.cpp $(COMMON_CCFILES)
TESTPROG_CUFILES := $(COMMON_CUFILES)
TESTPROG_OBJS := $(TESTPROG_CCFILES:%.cpp=$(TMPDIR)/%.o)
TESTPROG_OBJS += $(TESTPROG_CUFILES:%.cu=$(TMPDIR)/%.o)
DEPS := $(TESTPROG_CCFILES:%.cpp=$(TMPDIR)/%.d)

PROGNAME_CFILES := libcrypt.c libcryptsetup/keyencryption.c \
	libcryptsetup/setup.c libcryptsetup/utils_device.c \
	libcryptsetup/libdevmapper.c libcryptsetup/crypto_storage.c	\
	libcryptsetup/utils.c libcryptsetup/random.c \
	libcryptsetup/volumekey.c libcryptsetup/utils_crypt.c \
	libcryptsetup/utils_loop.c libcryptsetup/crypto_cipher_kernel.c \
	libcryptsetup/crypto_gcrypt.c
PROGNAME_CCFILES := hashsearch.cpp passGen.cpp $(COMMON_CCFILES)
PROGNAME_CUFILES := $(COMMON_CUFILES)
PROGNAME_OBJS := $(PROGNAME_CFILES:%.c=$(TMPDIR)/%.o)
PROGNAME_OBJS += $(PROGNAME_CCFILES:%.cpp=$(TMPDIR)/%.o)
PROGNAME_OBJS += $(PROGNAME_CUFILES:%.cu=$(TMPDIR)/%.o)
DEPS += $(PROGNAME_CCFILES:%.cpp=$(TMPDIR)/%.d)

all: $(TESTPROG) $(PROGNAME)

-include $(DEPS)

$(TESTPROG) : $(TESTPROG_OBJS)
	$(NVCC) -o $@ $^ `libgcrypt-config --libs`

$(PROGNAME) : $(PROGNAME_OBJS)
	$(NVCC) --linker-options --gc-sections,$(LDFLAGS) -o $@ $^ `libgcrypt-config --libs` -ldevmapper -luuid

$(TMPDIR)/%.o : %.c
	@if [ ! -e `dirname $@` ]; then mkdir -p `dirname $@`; fi
	$(CC) $(CFLAGS) -o $@ `libgcrypt-config --cflags` -MMD -MP -MF $(@:%.o=%.d) -c $<

$(TMPDIR)/%.o : %.cpp
	@if [ ! -e `dirname $@` ]; then mkdir -p `dirname $@`; fi
	$(CXX) $(CCFLAGS) -o $@ `libgcrypt-config --cflags` -MMD -MP -MF $(@:%.o=%.d) -c $<

$(TMPDIR)/%.o : %.cu
	@if [ ! -e `dirname $@` ]; then mkdir -p `dirname $@`; fi
	$(NVCC) $(NVCCFLAGS) -dc -o $@ $^

test: $(TESTPROG)
	./$(TESTPROG)
	echo $$?

exec: $(PROGNAME)
	./$(PROGNAME) head ab**
	echo $$?

clean:
	rm -rf $(TMPDIR)
	rm $(TESTPROG)
	rm $(PROGNAME)

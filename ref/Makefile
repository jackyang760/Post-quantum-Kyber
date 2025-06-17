CC ?= /usr/bin/cc
CFLAGS += -Wall -Wextra -Wpedantic -Wmissing-prototypes -Wredundant-decls \
  -Wshadow -Wpointer-arith -O3 -fomit-frame-pointer -z noexecstack
NISTFLAGS += -Wno-unused-result -O3 -fomit-frame-pointer
RM = /bin/rm

SOURCES = kem.c indcpa.c polyvec.c poly.c ntt.c cbd.c reduce.c verify.c
SOURCESASCON = $(SOURCES) ascon_hash.c symmetric.c 
HEADERS = params.h kem.h indcpa.h polyvec.h poly.h ntt.h cbd.h reduce.c verify.h symmetric.h
HEADERSASCON = $(HEADERS) ascon_hash.h ascon.h constants.h permutations.h round.h word.h 

.PHONY: all speed shared clean

all: test speed shared 

test: \
  test/test_kyber512 \
  test/test_kyber768 \
  test/test_kyber1024 \

speed: \
  test/test_speed512 \
  test/test_speed768 \
  test/test_speed1024 \

shared: \
  lib/libpqcrystals_kyber512_ref.so \
  lib/libpqcrystals_kyber768_ref.so \
  lib/libpqcrystals_kyber1024_ref.so \

# 构建共享库（Kyber各安全级别 + Ascon）
lib/libpqcrystals_kyber512_ref.so: $(SOURCESASCON) $(HEADERSASCON)
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=2 $(SOURCESASCON) -o $@

lib/libpqcrystals_kyber768_ref.so: $(SOURCESASCON) $(HEADERSASCON)
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=3 $(SOURCESASCON) -o $@

lib/libpqcrystals_kyber1024_ref.so: $(SOURCESASCON) $(HEADERSASCON)
	mkdir -p lib
	$(CC) -shared -fPIC $(CFLAGS) -DKYBER_K=4 $(SOURCESASCON) -o $@

# 测试用例（KYBER_K=2/3/4）
test/test_kyber512: $(SOURCESASCON) $(HEADERSASCON) test/test_kyber.c randombytes.c
	mkdir -p test
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCESASCON) randombytes.c test/test_kyber.c -o $@

test/test_kyber768: $(SOURCESASCON) $(HEADERSASCON) test/test_kyber.c randombytes.c
	mkdir -p test
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCESASCON) randombytes.c test/test_kyber.c -o $@

test/test_kyber1024: $(SOURCESASCON) $(HEADERSASCON) test/test_kyber.c randombytes.c
	mkdir -p test
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESASCON) randombytes.c test/test_kyber.c -o $@

# 性能测试
test/test_speed512: $(SOURCESASCON) $(HEADERSASCON) test/cpucycles.h test/cpucycles.c test/speed_print.h test/speed_print.c test/test_speed.c randombytes.c
	mkdir -p test
	$(CC) $(CFLAGS) -DKYBER_K=2 $(SOURCESASCON) randombytes.c test/cpucycles.c test/speed_print.c test/test_speed.c -o $@

test/test_speed768: $(SOURCESASCON) $(HEADERSASCON) test/cpucycles.h test/cpucycles.c test/speed_print.h test/speed_print.c test/test_speed.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=3 $(SOURCESASCON) randombytes.c test/cpucycles.c test/speed_print.c test/test_speed.c -o $@

test/test_speed1024: $(SOURCESASCON) $(HEADERSASCON) test/cpucycles.h test/cpucycles.c test/speed_print.h test/speed_print.c test/test_speed.c randombytes.c
	$(CC) $(CFLAGS) -DKYBER_K=4 $(SOURCESASCON) randombytes.c test/cpucycles.c test/speed_print.c test/test_speed.c -o $@

clean:
	-$(RM) -f *.gcno *.gcda *.lcov *.o *.so
	-$(RM) -f test/test_kyber512
	-$(RM) -f test/test_kyber768
	-$(RM) -f test/test_kyber1024
	-$(RM) -f test/test_speed512
	-$(RM) -f test/test_speed768
	-$(RM) -f test/test_speed1024
	-$(RM) -rf lib/


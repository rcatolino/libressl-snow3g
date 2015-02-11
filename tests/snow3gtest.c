/* $OpenBSD: snow3gtest.c,v 0.10 2015 raphael.catolino@gmail.com$ */

/**
 * snow 3g stream cipher test.
 *
 * This code is hereby placed in the public domain.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ''AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * The test vectors can be found at :
 * http://www.gsma.com/technicalprojects/wp-content/uploads/2012/04/Doc3-UEA2-UIA2-Spec-Implementors-Test-Data.pdf
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/snow3g.h>

struct snow_tv {
  struct snow_key_st key;
  uint32_t lfsr_before_init[SNOW_KEY_SIZE];
  uint32_t lfsr_after_init[SNOW_KEY_SIZE];
  struct fsm_st fsm_after_init;
  // First words from keystream
  uint32_t keystream[2];
};

struct snow_tv snow_tvs[] = {
  {
    {
      { 0x2BD6459F, 0x82C5B300, 0x952C4910, 0x4881FF48, },
      { 0xEA024714, 0xAD5C4D84, 0xDF1F9B25, 0x1C0BF45F, },
    },
    {
      0xD429BA60, 0x7D3A4CFF, 0x6AD3B6EF, 0xB77E00B7,
      0x2BD6459F, 0x82C5B300, 0x952C4910, 0x4881FF48,
      0xD429BA60, 0x6131B8A0, 0xB5CC2DCA, 0xB77E00B7,
      0x868A081B, 0x82C5B300, 0x952C4910, 0xA283B85C,
    },
    {
      0x8F1215A6, 0xE003A052, 0x9241C929, 0x68D7BF8C,
      0x16BF4C2A, 0x8DEF9D70, 0x32381704, 0x11DD346A,
      0xE18B81EA, 0x77EBD4FE, 0x57ED9505, 0x0C33C0EF,
      0x1A037B59, 0x97591E82, 0xA91CCB44, 0x7B48E04F,
    },
    { 0x61DA9249, 0x427DF38C, 0x0FB6B101, },
    { 0xABEE9704, 0x7AC31373, },
  },
  {
    {
      { 0x8CE33E2C, 0xC3C0B5FC, 0x1F3DE8A6, 0xDC66B1F3, },
      { 0xD3C5D592, 0x327FB11C, 0xDE551988, 0xCEB2F9B7, },
    },
    {
      0x731CC1D3, 0x3C3F4A03, 0xE0C21759, 0x23994E0C,
      0x8CE33E2C, 0xC3C0B5FC, 0x1F3DE8A6, 0xDC66B1F3,
      0x731CC1D3, 0xF28DB3B4, 0x3E970ED1, 0x23994E0C,
      0xBE9C8F30, 0xC3C0B5FC, 0x1F3DE8A6, 0x0FA36461,
    },
    {
      0x04D6A929, 0x942E1440, 0x82ABD3FE, 0x5832E9F4,
      0x5F9702A0, 0x08712C81, 0x644CC9B9, 0xDBF6DE13,
      0xBAA5B1D0, 0x92E9DD53, 0xA2E2FA6D, 0xCE6965AA,
      0x02C0CD4E, 0x6E6D984F, 0x114A90E7, 0x5279F8DA,
    },
    { 0x65130120, 0xA14C7DBD, 0xB68B551A, },
    { 0xEFF8A342, 0xF751480F, },
  },
  {
    {
      { 0x4035C668, 0x0AF8C6D1, 0xA8FF8667, 0xB1714013, },
      { 0x62A54098, 0x1BA6F9B7, 0x4592B0E7, 0x8690F71B, },
    },
    {
      0xBFCA3997, 0xF507392E, 0x57007998, 0x4E8EBFEC,
      0x4035C668, 0x0AF8C6D1, 0xA8FF8667, 0xB1714013,
      0xBFCA3997, 0x7397CE35, 0x1292C97F, 0x4E8EBFEC,
      0x5B933FDF, 0x0AF8C6D1, 0xA8FF8667, 0xD3D4008B,
    },
    {
      0xFEAFBAD8, 0x1B11050A, 0x23708014, 0xAC8494DB,
      0xED97D431, 0xDBBB59B3, 0x6CD30005, 0x7EC36405,
      0xB20F02AC, 0xEB407735, 0x50E41A0E, 0xFFA8ABC1,
      0xEB4800A7, 0xD4E6749D, 0xD1C452FE, 0xA92A3153,
    },
    { 0x6599AA50, 0x5EA9188B, 0xF41889FC, },
    { 0xA8C874A9, 0x7AE7C4F8, },
  },
};

#define N_VECTORS (sizeof(snow_tvs) / sizeof(*snow_tvs))

int
test_before_init(struct snow_tv *tv)
{
  return 0;
}

int
test_snow_full(struct snow_tv *tv)
{
  int failed = 0;
  return failed;
}

void
print_lfsr(uint32_t *lfsr)
{
  size_t i;
  for (i = 0; i < SNOW_KEY_SIZE; i += 4) {
    printf("0x%08X 0x%08X 0x%08X 0x%08X\n", lfsr[i], lfsr[i+1], lfsr[i+2], lfsr[i+3]);
  }
}

void snow_init_lfsr_fsm(struct snow_key_st key, snow_ctx *ctx);

int
main(int argc, char **argv)
{
  size_t i;
  int failed = 0;

	for (i = 0; i < N_VECTORS; i++) {
    struct snow_tv *tv = snow_tvs+i;
    snow_ctx ctx;
    snow_init_lfsr_fsm(tv->key, &ctx);
    if (memcmp(&ctx.lfsr, &tv->lfsr_before_init, sizeof(uint32_t)*SNOW_KEY_SIZE)) {
      printf("Error, unexpected lfsr state before inititalization. Expected : \n");
      print_lfsr(tv->lfsr_before_init);
      printf("Got :\n");
      print_lfsr(ctx.lfsr);
      failed = -1;
    }
  }

  return failed;
}

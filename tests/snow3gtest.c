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

struct snow_tv2 {
  struct snow_key_st key;
  uint32_t z2500;
};

struct snow_tv {
  struct snow_key_st key;
  uint32_t lfsr_before_init[SNOW_KEY_SIZE];
  struct fsm_st fsm_after_clock;
  uint32_t lfsr_after_init[SNOW_KEY_SIZE];
  struct fsm_st fsm_after_init;
  // First words from keystream
  uint32_t keystream[2];
};

struct uea2_tv {
  uint32_t countc;
  uint8_t bearer;
  uint8_t direction;
  char confidentiality_key[SNOW_KEY_SIZE];
  uint32_t keystream[32];
  ssize_t nb_word;
};

struct snow_tv2 tv2 = {
  {
    { 0x0DED7263, 0x109CF92E, 0x3352255A, 0x140E0F76, },
    { 0x6B68079A, 0x41A7C4C9, 0x1BEFD79F, 0x7FDCC233, },
  },
  0x9C0DB3AA,
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
    { 0x82C5B300, 0x63636363, 0x25252525, },
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
    { 0xC3C0B5FC, 0x63636363, 0x25252525, },
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
    { 0x0AF8C6D1, 0x63636363, 0x25252525, },
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

struct uea2_tv uea2_test = {
  0x72A4F20F,
  0x0C,
  1,
  { 0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00,
    0x95, 0x2C, 0x49, 0x10, 0x48, 0x81, 0xFF, 0x48 },
  { 0xF22DB45B,  0x37E71C5B,  0x4EB6F404,  0xCD886C15,
    0x9DCA27B1,  0xF062AF46,  0xF8E2F587,  0x8976E8B8,
    0x33E2B848,  0xE798969D,  0x85E5961A,  0x057983F1,
    0x10F55076,  0x71185285,  0xD53CED16,  0xFD580500,
    0x7BEE12BE,  0x1C5C52EC,  0x78C12E8A,  0xC5B1B9D5,
    0x3BF90900,  0xDF06DF63,  0x3C3C15D5,  0xC270DE52,
    0xFB4D09C3,
  },
  25,
};

#define N_VECTORS (sizeof(snow_tvs) / sizeof(*snow_tvs))

void
print_fsm(struct fsm_st fsm) {
  printf("0x%08X 0x%08X 0x%08X\n", fsm.r1, fsm.r2, fsm.r3);
}

void
print_lfsr(uint32_t *lfsr)
{
  size_t i;
  for (i = 0; i < SNOW_KEY_SIZE; i += 4) {
    printf("0x%08X 0x%08X 0x%08X 0x%08X\n", lfsr[i], lfsr[i+1], lfsr[i+2], lfsr[i+3]);
  }
}

void lfsr_init(uint32_t f, snow_ctx *ctx);
void lfsr_keystream(snow_ctx *ctx);
uint32_t clock_fsm(snow_ctx *ctx);
void snow_init_lfsr_fsm(struct snow_key_st key, snow_ctx *ctx);

int
main(int argc, char **argv)
{
  size_t i;
  int failed = 0;
  snow_ctx uea2_ctx;
  uint32_t uea2_keystream[25];

	for (i = 0; i < N_VECTORS; i++) {
    struct snow_tv *tv = snow_tvs+i;
    uint32_t keystream[2];
    uint32_t z;
    snow_ctx ctx;

    /* Test the init steps individually */
    snow_init_lfsr_fsm(tv->key, &ctx);
    if (memcmp(ctx.lfsr, tv->lfsr_before_init, sizeof(uint32_t)*SNOW_KEY_SIZE)) {
      printf("Error, unexpected lfsr state before inititalization. Expected : \n");
      print_lfsr(tv->lfsr_before_init);
      printf("Got :\n");
      print_lfsr(ctx.lfsr);
      failed = -1;
      break;
    }

    clock_fsm(&ctx);
    if (memcmp(&ctx.fsm, &tv->fsm_after_clock, sizeof(struct fsm_st))) {
      printf("Error, unexpected fsm state after first clocking. Expected : \n");
      print_fsm(tv->fsm_after_clock);
      printf("Got :\n");
      print_fsm(ctx.fsm);
      failed = -1;
      break;
    }

    /* Test the snow initialization as whole */
    memset(&ctx, 0, sizeof(ctx));
    SNOW_set_key(tv->key, &ctx);
    if (memcmp(ctx.lfsr, tv->lfsr_after_init, sizeof(uint32_t)*SNOW_KEY_SIZE)) {
      printf("Error, unexpected lfsr state after inititalization. Expected : \n");
      print_lfsr(tv->lfsr_after_init);
      printf("Got :\n");
      print_lfsr(ctx.lfsr);
      failed = -1;
      break;
    }

    if (memcmp(&ctx.fsm, &tv->fsm_after_init, sizeof(struct fsm_st))) {
      printf("Error, unexpected fsm state after inititalization. Expected : \n");
      print_fsm(tv->fsm_after_init);
      printf("Got :\n");
      print_fsm(ctx.fsm);
      failed = -1;
      break;
    }

    /* Tests on the actual keystream */
    SNOW_gen_keystream(keystream, sizeof(keystream)/sizeof(*keystream), &ctx);
    if (memcmp(keystream, tv->keystream, sizeof(keystream))) {
      printf("Error, unexpected keystream. Expected : \n");
      printf("0x%08X 0x%08X\n", tv->keystream[0], tv->keystream[1]);
      printf("Got :\n");
      printf("0x%08X 0x%08X\n", keystream[0], keystream[1]);
      failed = -1;
      break;
    }

    memset(&ctx, 0, sizeof(ctx));
    SNOW_set_key(tv2.key, &ctx);
    clock_fsm(&ctx);
    lfsr_keystream(&ctx);

    for (i = 0; i < 2500; i++) {
      z = clock_fsm(&ctx) ^ ctx.lfsr[0];
      lfsr_keystream(&ctx);
    }

    if (z != tv2.z2500) {
      printf("Error, bad keystream. Expected z2500 = 0x08%X. Got 0x08%X\n",
          tv2.z2500, z);
      failed = -1;
      break;
    }
  }

  /* Test the snow cipher as the UEA2 algorithm */
  /* SNOW_init(uea2_test.countc, uea2_test.bearer, uea2_test.direction,
      uea2_test.confidentiality_key, &uea2_ctx); */

  // TODO FINISH
  struct snow_key_st snow_key;
  memset(&snow_key, 0, sizeof(snow_key));

#define WORD_128(array, i) be32toh(((uint32_t *)array)[i]);
  snow_key.key[3] = WORD_128(uea2_test.confidentiality_key, 0);
  snow_key.key[2] = WORD_128(uea2_test.confidentiality_key, 1);
  snow_key.key[1] = WORD_128(uea2_test.confidentiality_key, 2);
  snow_key.key[0] = WORD_128(uea2_test.confidentiality_key, 3);

  printf("0x%08X 0x%08X 0x%08X 0x%08X\n", snow_key.key[0], snow_key.key[1],
      snow_key.key[2], snow_key.key[3]);

  snow_key.iv[3] = uea2_test.countc;
  snow_key.iv[2] = ((uea2_test.bearer & 0x1F) << 27) | ((uea2_test.direction & 0x01) << 26);
  snow_key.iv[1] = snow_key.iv[3];
  snow_key.iv[0] = snow_key.iv[2];

  printf("0x%08X 0x%08X 0x%08X 0x%08X\n", snow_key.iv[0], snow_key.iv[1],
      snow_key.iv[2], snow_key.iv[3]);

  SNOW_set_key(snow_key, &uea2_ctx);
  SNOW_gen_keystream(uea2_keystream, uea2_test.nb_word, &uea2_ctx);
  for (int i = 0; i < uea2_test.nb_word; i++) {
    printf("0x%08X | 0x%08X\n", uea2_keystream[i], uea2_test.keystream[i]);
  }

  if (memcmp(uea2_keystream, uea2_test.keystream, sizeof(uea2_keystream))) {
    printf("Error, bad keystream for uea2.\n");
    failed = -1;
  }

  return failed;
}

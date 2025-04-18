#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <webp/decode.h>
#include <webp/encode.h>
#include <webp/types.h>

#define MAX_IMAGE_DIM 16384
#define MAX_ENCODE_QUALITY 90
#define MIN_ENCODE_QUALITY 10

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 12) return 0;

    int width = 0, height = 0;
    uint8_t *decoded_rgba = WebPDecodeRGBA(data, size, &width, &height);
    if (!decoded_rgba) return 0;

    if (width <= 0 || height <= 0 || width > MAX_IMAGE_DIM || height > MAX_IMAGE_DIM) {
        free(decoded_rgba);
        return 0;
    }
    uint8_t *encoded_webp = NULL;
    size_t encoded_size = WebPEncodeRGBA(
        decoded_rgba, width, height, width * 4,
        (rand() % (MAX_ENCODE_QUALITY - MIN_ENCODE_QUALITY)) + MIN_ENCODE_QUALITY,
        &encoded_webp
    );

    if (encoded_size > 0 && encoded_webp) {
        int width2 = 0, height2 = 0;
        uint8_t *decoded2 = WebPDecodeRGBA(encoded_webp, encoded_size, &width2, &height2);
        if (decoded2) {
            free(decoded2);
        }
        free(encoded_webp);
    }

    free(decoded_rgba);
    return 0;
}

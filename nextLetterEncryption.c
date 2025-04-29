#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <argon2.h>
#include <zlib.h>

// Constants
#define VERSION "01"
#define SALT_LENGTH 16
#define IV_LENGTH 12
#define HMAC_LENGTH 32
#define AES_KEY_LENGTH 16
#define HMAC_KEY_LENGTH 16
#define BLOCK_SIZE 64
#define MAX_PASSES 3
#define MAX_MESSAGE_LENGTH (1024 * 1024) // 1MB max
#define SUB_TABLE_SIZE 256

// Error codes
typedef enum {
    CRYPTO_OK = 0,
    CRYPTO_INVALID_INPUT,
    CRYPTO_MEMORY_ERROR,
    CRYPTO_CRYPTO_ERROR,
    CRYPTO_COMPRESSION_ERROR,
    CRYPTO_HMAC_ERROR,
    CRYPTO_VERSION_ERROR,
    CRYPTO_LENGTH_ERROR
} CryptoError;

// Configuration structure
typedef struct {
    size_t padding_length;
    int use_compression;
    uint8_t passes;
    uint32_t timestamp;
} Config;

// Global substitution table (initialized at runtime)
static uint8_t sub_table[SUB_TABLE_SIZE];

// Initialize substitution table
void init_sub_table(void) {
    for (int i = 0; i < SUB_TABLE_SIZE; i++) {
        sub_table[i] = (uint8_t)i;
    }
    // Shuffle table using Fisher-Yates
    for (int i = SUB_TABLE_SIZE - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        uint8_t temp = sub_table[i];
        sub_table[i] = sub_table[j];
        sub_table[j] = temp;
    }
}

// Base64 encoding
char* base64_encode(const uint8_t* data, size_t len) {
    const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t out_len = ((len + 2) / 3) * 4 + 1;
    char* result = (char*)calloc(out_len, sizeof(char));
    if (!result) return NULL;

    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t triple = (a << 16) + (b << 8) + c;
        result[j++] = b64[(triple >> 18) & 63];
        result[j++] = b64[(triple >> 12) & 63];
        result[j++] = (i > len + 1) ? '=' : b64[(triple >> 6) & 63];
        result[j++] = (i > len) ? '=' : b64[triple & 63];
    }
    result[j] = '\0';
    return result;
}

// Base64 decoding
uint8_t* base64_decode(const char* input, size_t* out_len) {
    const char* b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t len = strlen(input);
    if (len % 4 != 0) return NULL;

    *out_len = (len / 4) * 3;
    if (input[len-1] == '=') (*out_len)--;
    if (input[len-2] == '=') (*out_len)--;

    uint8_t* result = (uint8_t*)malloc(*out_len);
    if (!result) return NULL;

    size_t i = 0, j = 0;
    while (i < len) {
        uint32_t a = input[i] == '=' ? 0 : strchr(b64, input[i++]) - b64;
        uint32_t b = input[i] == '=' ? 0 : strchr(b64, input[i++]) - b64;
        uint32_t c = input[i] == '=' ? 0 : strchr(b64, input[i++]) - b64;
        uint32_t d = input[i] == '=' ? 0 : strchr(b64, input[i++]) - b64;
        uint32_t triple = (a << 18) + (b << 12) + (c << 6) + d;
        result[j++] = (triple >> 16) & 255;
        if (input[i-2] != '=') result[j++] = (triple >> 8) & 255;
        if (input[i-1] != '=') result[j++] = triple & 255;
    }
    return result;
}

// Generate random bytes
CryptoError generate_random_bytes(uint8_t* bytes, size_t len) {
    if (RAND_bytes(bytes, len) != 1) {
        return CRYPTO_CRYPTO_ERROR;
    }
    return CRYPTO_OK;
}

// Compress data
CryptoError compress(const uint8_t* data, size_t len, uint8_t** compressed, size_t* comp_len) {
    z_stream zs = {0};
    if (deflateInit(&zs, Z_BEST_COMPRESSION) != Z_OK) {
        return CRYPTO_COMPRESSION_ERROR;
    }

    zs.next_in = (Bytef*)data;
    zs.avail_in = len;
    size_t buffer_size = deflateBound(&zs, len);
    *compressed = (uint8_t*)malloc(buffer_size);
    if (!*compressed) {
        deflateEnd(&zs);
        return CRYPTO_MEMORY_ERROR;
    }

    zs.next_out = *compressed;
    zs.avail_out = buffer_size;
    int ret = deflate(&zs, Z_FINISH);
    if (ret != Z_STREAM_END) {
        free(*compressed);
        deflateEnd(&zs);
        return CRYPTO_COMPRESSION_ERROR;
    }

    *comp_len = zs.total_out;
    deflateEnd(&zs);
    return CRYPTO_OK;
}

// Decompress data
CryptoError decompress(const uint8_t* compressed, size_t comp_len, uint8_t** decompressed, size_t* dec_len) {
    z_stream zs = {0};
    if (inflateInit(&zs) != Z_OK) {
        return CRYPTO_COMPRESSION_ERROR;
    }

    zs.next_in = (Bytef*)compressed;
    zs.avail_in = comp_len;
    *dec_len = comp_len * 4; // Initial guess
    *decompressed = (uint8_t*)malloc(*dec_len);
    if (!*decompressed) {
        inflateEnd(&zs);
        return CRYPTO_MEMORY_ERROR;
    }

    zs.next_out = *decompressed;
    zs.avail_out = *dec_len;
    int ret = inflate(&zs, Z_NO_FLUSH);
    if (ret != Z_STREAM_END) {
        free(*decompressed);
        inflateEnd(&zs);
        return CRYPTO_COMPRESSION_ERROR;
    }

    *dec_len = zs.total_out;
    inflateEnd(&zs);
    return CRYPTO_OK;
}

// Derive keys with Argon2
CryptoError derive_keys(const char* key, const uint8_t* salt, size_t salt_len, Config* config,
                       uint8_t** enc_key, uint8_t** hmac_key) {
    size_t hash_len = AES_KEY_LENGTH + HMAC_KEY_LENGTH;
    uint8_t* hash = (uint8_t*)malloc(hash_len);
    if (!hash) return CRYPTO_MEMORY_ERROR;

    uint32_t t_cost = 4;
    uint32_t m_cost = 65536;
    uint32_t parallelism = 2;
    int ret = argon2id_hash_raw(t_cost, m_cost, parallelism, key, strlen(key),
                               salt, salt_len, hash, hash_len);
    if (ret != ARGON2_OK) {
        free(hash);
        return CRYPTO_CRYPTO_ERROR;
    }

    *enc_key = (uint8_t*)malloc(AES_KEY_LENGTH);
    *hmac_key = (uint8_t*)malloc(HMAC_KEY_LENGTH);
    if (!*enc_key || !*hmac_key) {
        free(hash);
        free(*enc_key);
        free(*hmac_key);
        return CRYPTO_MEMORY_ERROR;
    }

    memcpy(*enc_key, hash, AES_KEY_LENGTH);
    memcpy(*hmac_key, hash + AES_KEY_LENGTH, HMAC_KEY_LENGTH);
    free(hash);
    return CRYPTO_OK;
}

// Compute HMAC
CryptoError compute_hmac(const uint8_t* data, size_t len, const uint8_t* hmac_key, size_t key_len,
                        uint8_t** hmac, size_t* hmac_len) {
    *hmac = (uint8_t*)malloc(HMAC_LENGTH);
    if (!*hmac) return CRYPTO_MEMORY_ERROR;

    unsigned int len_out = HMAC_LENGTH;
    HMAC(EVP_sha256(), hmac_key, key_len, data, len, *hmac, &len_out);
    *hmac_len = len_out;
    return CRYPTO_OK;
}

// Verify HMAC
int verify_hmac(const uint8_t* data, size_t data_len, const uint8_t* hmac, size_t hmac_len,
                const uint8_t* hmac_key, size_t key_len) {
    uint8_t* computed_hmac = NULL;
    size_t computed_len = 0;
    if (compute_hmac(data, data_len, hmac_key, key_len, &computed_hmac, &computed_len) != CRYPTO_OK) {
        return 0;
    }

    if (hmac_len != computed_len) {
        free(computed_hmac);
        return 0;
    }

    int result = 0;
    for (size_t i = 0; i < hmac_len; i++) {
        result |= hmac[i] ^ computed_hmac[i];
    }
    free(computed_hmac);
    return result == 0;
}

// Non-linear transformation
void apply_non_linear(uint8_t* data, size_t len, uint32_t seed) {
    for (size_t i = 0; i < len; i++) {
        uint32_t x = data[i] ^ (seed >> (i % 32));
        data[i] = sub_table[x & 0xFF];
    }
}

// Dynamic offset calculation
uint32_t calc_dynamic_offset(size_t pos, size_t len, uint32_t timestamp) {
    return (uint32_t)(pos * 17 + len * 13 + timestamp) ^ (pos << 3);
}

// Encrypt block with multiple passes
CryptoError encrypt_block(uint8_t* block, size_t block_len, const uint8_t* enc_key,
                         const uint8_t* iv, Config* config, uint8_t** ciphertext, size_t* cipher_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return CRYPTO_CRYPTO_ERROR;

    *ciphertext = (uint8_t*)malloc(block_len + 16);
    if (!*ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_MEMORY_ERROR;
    }

    int len, cipher_len_temp;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, enc_key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, *ciphertext, &len, block, block_len) != 1) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_CRYPTO_ERROR;
    }
    cipher_len_temp = len;

    if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &len) != 1) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_CRYPTO_ERROR;
    }
    cipher_len_temp += len;

    uint8_t tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        free(*ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_CRYPTO_ERROR;
    }

    *cipher_len = cipher_len_temp;
    memcpy(*ciphertext + cipher_len_temp, tag, 16);
    *cipher_len += 16;
    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_OK;
}

// Decrypt block
CryptoError decrypt_block(uint8_t* ciphertext, size_t cipher_len, const uint8_t* enc_key,
                         const uint8_t* iv, uint8_t** plaintext, size_t* plain_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return CRYPTO_CRYPTO_ERROR;

    *plaintext = (uint8_t*)malloc(cipher_len);
    if (!*plaintext) {
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_MEMORY_ERROR;
    }

    uint8_t* tag = ciphertext + cipher_len - 16;
    int len, plain_len_temp;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, enc_key, iv) != 1 ||
        EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, cipher_len - 16) != 1) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_CRYPTO_ERROR;
    }
    plain_len_temp = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) != 1 ||
        EVP_DecryptFinal_ex(ctx, *plaintext + len, &len) <= 0) {
        free(*plaintext);
        EVP_CIPHER_CTX_free(ctx);
        return CRYPTO_CRYPTO_ERROR;
    }
    plain_len_temp += len;

    *plain_len = plain_len_temp;
    EVP_CIPHER_CTX_free(ctx);
    return CRYPTO_OK;
}

// Main encryption function
CryptoError encrypt(const char* message, const char* key, Config* config, char** output) {
    if (!message || !key || !output || strlen(message) == 0 || strlen(key) == 0 ||
        strlen(message) > MAX_MESSAGE_LENGTH || config->padding_length > 128) {
        return CRYPTO_INVALID_INPUT;
    }

    // Initialize configuration
    config->timestamp = (uint32_t)time(NULL);
    srand(config->timestamp);
    init_sub_table();

    // Convert message to bytes (UTF-8)
    size_t msg_len = strlen(message);
    uint8_t* data = (uint8_t*)malloc(msg_len + 1);
    if (!data) return CRYPTO_MEMORY_ERROR;
    memcpy(data, message, msg_len + 1);

    // Compress if enabled
    uint8_t* processed = data;
    size_t proc_len = msg_len;
    if (config->use_compression) {
        if (compress(data, msg_len, &processed, &proc_len) != CRYPTO_OK) {
            free(data);
            return CRYPTO_COMPRESSION_ERROR;
        }
        free(data);
    }

    // Add padding and salt
    size_t total_len = proc_len + config->padding_length + SALT_LENGTH;
    uint8_t* padded = (uint8_t*)malloc(total_len);
    if (!padded) {
        free(processed);
        return CRYPTO_MEMORY_ERROR;
    }
    memcpy(padded, processed, proc_len);
    if (generate_random_bytes(padded + proc_len, SALT_LENGTH) != CRYPTO_OK ||
        generate_random_bytes(padded + proc_len + SALT_LENGTH, config->padding_length) != CRYPTO_OK) {
        free(padded);
        free(processed);
        return CRYPTO_CRYPTO_ERROR;
    }
    free(processed);

    // Apply non-linear transformation
    apply_non_linear(padded, total_len, config->timestamp);

    // Generate keys
    uint8_t salt[SALT_LENGTH];
    if (generate_random_bytes(salt, SALT_LENGTH) != CRYPTO_OK) {
        free(padded);
        return CRYPTO_CRYPTO_ERROR;
    }

    uint8_t* enc_key = NULL;
    uint8_t* hmac_key = NULL;
    if (derive_keys(key, salt, SALT_LENGTH, config, &enc_key, &hmac_key) != CRYPTO_OK) {
        free(padded);
        return CRYPTO_CRYPTO_ERROR;
    }

    // Process in blocks with multiple passes
    uint8_t* final_data = NULL;
    size_t final_len = 0;
    size_t num_blocks = (total_len + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (int pass = 0; pass < config->passes; pass++) {
        uint8_t* temp_data = (uint8_t*)malloc(total_len + 16 * num_blocks);
        if (!temp_data) {
            free(padded);
            free(enc_key);
            free(hmac_key);
            free(final_data);
            return CRYPTO_MEMORY_ERROR;
        }
        size_t temp_len = 0;

        for (size_t i = 0; i < num_blocks; i++) {
            size_t block_len = (i == num_blocks - 1) ? total_len - i * BLOCK_SIZE : BLOCK_SIZE;
            uint8_t* block = padded + i * BLOCK_SIZE;
            uint8_t iv[IV_LENGTH];
            if (generate_random_bytes(iv, IV_LENGTH) != CRYPTO_OK) {
                free(temp_data);
                free(padded);
                free(enc_key);
                free(hmac_key);
                free(final_data);
                return CRYPTO_CRYPTO_ERROR;
            }

            uint8_t* cipher_block = NULL;
            size_t cipher_block_len = 0;
            if (encrypt_block(block, block_len, enc_key, iv, config, &cipher_block, &cipher_block_len) != CRYPTO_OK) {
                free(temp_data);
                free(padded);
                free(enc_key);
                free(hmac_key);
                free(final_data);
                return CRYPTO_CRYPTO_ERROR;
            }

            memcpy(temp_data + temp_len, cipher_block, cipher_block_len);
            temp_len += cipher_block_len;
            free(cipher_block);
        }

        free(padded);
        padded = temp_data;
        total_len = temp_len;
    }

    final_data = padded;
    final_len = total_len;

    // Compute HMAC
    uint8_t* hmac_data = (uint8_t*)malloc(2 + SALT_LENGTH + IV_LENGTH + final_len);
    if (!hmac_data) {
        free(final_data);
        free(enc_key);
        free(hmac_key);
        return CRYPTO_MEMORY_ERROR;
    }
    memcpy(hmac_data, VERSION, 2);
    memcpy(hmac_data + 2, salt, SALT_LENGTH);
    memcpy(hmac_data + 2 + SALT_LENGTH, final_data, final_len);

    uint8_t* hmac = NULL;
    size_t hmac_len = 0;
    if (compute_hmac(hmac_data, 2 + SALT_LENGTH + final_len, hmac_key, HMAC_KEY_LENGTH, &hmac, &hmac_len) != CRYPTO_OK) {
        free(hmac_data);
        free(final_data);
        free(enc_key);
        free(hmac_key);
        return CRYPTO_CRYPTO_ERROR;
    }

    // Combine output
    size_t result_len = 2 + SALT_LENGTH + final_len + hmac_len;
    uint8_t* result = (uint8_t*)malloc(result_len);
    if (!result) {
        free(hmac_data);
        free(hmac);
        free(final_data);
        free(enc_key);
        free(hmac_key);
        return CRYPTO_MEMORY_ERROR;
    }
    memcpy(result, VERSION, 2);
    memcpy(result + 2, salt, SALT_LENGTH);
    memcpy(result + 2 + SALT_LENGTH, final_data, final_len);
    memcpy(result + 2 + SALT_LENGTH + final_len, hmac, hmac_len);

    *output = base64_encode(result, result_len);
    if (!*output) {
        free(hmac_data);
        free(hmac);
        free(final_data);
        free(enc_key);
        free(hmac_key);
        free(result);
        return CRYPTO_MEMORY_ERROR;
    }

    free(hmac_data);
    free(hmac);
    free(final_data);
    free(enc_key);
    free(hmac_key);
    free(result);
    return CRYPTO_OK;
}

// Main decryption function
CryptoError decrypt(const char* encrypted, const char* key, Config* config, char** output) {
    if (!encrypted || !key || !output || strlen(encrypted) == 0 || strlen(key) == 0) {
        return CRYPTO_INVALID_INPUT;
    }

    // Decode base64
    size_t data_len = 0;
    uint8_t* data = base64_decode(encrypted, &data_len);
    if (!data || data_len < 2 + SALT_LENGTH + IV_LENGTH + HMAC_LENGTH) {
        free(data);
        return CRYPTO_LENGTH_ERROR;
    }

    // Parse message
    if (memcmp(data, VERSION, 2) != 0) {
        free(data);
        return CRYPTO_VERSION_ERROR;
    }
    uint8_t* salt = data + 2;
    uint8_t* ciphertext = data + 2 + SALT_LENGTH;
    size_t cipher_len = data_len - (2 + SALT_LENGTH + HMAC_LENGTH);
    uint8_t* hmac = data + data_len - HMAC_LENGTH;

    // Derive keys
    uint8_t* enc_key = NULL;
    uint8_t* hmac_key = NULL;
    if (derive_keys(key, salt, SALT_LENGTH, config, &enc_key, &hmac_key) != CRYPTO_OK) {
        free(data);
        return CRYPTO_CRYPTO_ERROR;
    }

    // Verify HMAC
    if (!verify_hmac(data, data_len - HMAC_LENGTH, hmac, HMAC_LENGTH, hmac_key, HMAC_KEY_LENGTH)) {
        free(data);
        free(enc_key);
        free(hmac_key);
        return CRYPTO_HMAC_ERROR;
    }

    // Process blocks in reverse passes
    uint8_t* processed = ciphertext;
    size_t proc_len = cipher_len;
    size_t num_blocks = (proc_len + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (int pass = config->passes - 1; pass >= 0; pass--) {
        uint8_t* temp_data = (uint8_t*)malloc(proc_len);
        if (!temp_data) {
            free(data);
            free(enc_key);
            free(hmac_key);
            if (processed != ciphertext) free(processed);
            return CRYPTO_MEMORY_ERROR;
        }
        size_t temp_len = 0;

        for (size_t i = 0; i < num_blocks; i++) {
            size_t block_len = (i == num_blocks - 1) ? proc_len - i * BLOCK_SIZE : BLOCK_SIZE;
            uint8_t* block = processed + i * BLOCK_SIZE;
            uint8_t iv[IV_LENGTH];
            if (generate_random_bytes(iv, IV_LENGTH) != CRYPTO_OK) {
                free(temp_data);
                free(data);
                free(enc_key);
                free(hmac_key);
                if (processed != ciphertext) free(processed);
                return CRYPTO_CRYPTO_ERROR;
            }

            uint8_t* plain_block = NULL;
            size_t plain_block_len = 0;
            if (decrypt_block(block, block_len, enc_key, iv, &plain_block, &plain_block_len) != CRYPTO_OK) {
                free(temp_data);
                free(data);
                free(enc_key);
                free(hmac_key);
                if (processed != ciphertext) free(processed);
                return CRYPTO_CRYPTO_ERROR;
            }

            memcpy(temp_data + temp_len, plain_block, plain_block_len);
            temp_len += plain_block_len;
            free(plain_block);
        }

        if (processed != ciphertext) free(processed);
        processed = temp_data;
        proc_len = temp_len;
    }

    // Reverse non-linear transformation
    apply_non_linear(processed, proc_len, config->timestamp);

    // Remove padding and salt
    if (proc_len < config->padding_length + SALT_LENGTH) {
        free(processed);
        free(data);
        free(enc_key);
        free(hmac_key);
        return CRYPTO_LENGTH_ERROR;
    }
    proc_len -= (config->padding_length + SALT_LENGTH);

    // Decompress if enabled
    uint8_t* final_data = processed;
    size_t final_len = proc_len;
    if (config->use_compression) {
        if (decompress(processed, proc_len, &final_data, &final_len) != CRYPTO_OK) {
            free(processed);
            free(data);
            free(enc_key);
            free(hmac_key);
            return CRYPTO_COMPRESSION_ERROR;
        }
        free(processed);
    }

    *output = (char*)malloc(final_len + 1);
    if (!*output) {
        free(final_data);
        free(data);
        free(enc_key);
        free(hmac_key);
        return CRYPTO_MEMORY_ERROR;
    }
    memcpy(*output, final_data, final_len);
    (*output)[final_len] = '\0';

    free(final_data);
    free(data);
    free(enc_key);
    free(hmac_key);
    return CRYPTO_OK;
}

// Error message helper
const char* get_error_message(CryptoError err) {
    switch (err) {
        case CRYPTO_OK: return "Success";
        case CRYPTO_INVALID_INPUT: return "Invalid input parameters";
        case CRYPTO_MEMORY_ERROR: return "Memory allocation failed";
        case CRYPTO_CRYPTO_ERROR: return "Cryptographic operation failed";
        case CRYPTO_COMPRESSION_ERROR: return "Compression/decompression failed";
        case CRYPTO_HMAC_ERROR: return "HMAC verification failed";
        case CRYPTO_VERSION_ERROR: return "Unsupported version";
        case CRYPTO_LENGTH_ERROR: return "Invalid data length";
        default: return "Unknown error";
    }
}

// Main CLI
int main(void) {
    char mode[16], *message = NULL, *key = NULL;
    size_t message_len = 0, key_len = 0;
    Config config = {16, 1, MAX_PASSES, 0};
    char* padding_input = NULL;

    printf("Advanced Encryption Tool\n");
    printf("Mode (encrypt/decrypt): ");
    if (!fgets(mode, sizeof(mode), stdin)) {
        printf("Error reading mode\n");
        return 1;
    }
    mode[strcspn(mode, "\n")] = '\0';

    printf("Message: ");
    if (getline(&message, &message_len, stdin) == -1) {
        printf("Error reading message\n");
        return 1;
    }
    message[strcspn(message, "\n")] = '\0';

    printf("Key: ");
    if (getline(&key, &key_len, stdin) == -1) {
        free(message);
        printf("Error reading key\n");
        return 1;
    }
    key[strcspn(key, "\n")] = '\0';

    printf("Padding length (0-128, default 16): ");
    if (getline(&padding_input, &message_len, stdin) == -1) {
        free(message);
        free(key);
        printf("Error reading padding\n");
        return 1;
    }
    if (padding_input[0] != '\n') {
        config.padding_length = atoi(padding_input);
    }

    printf("Use compression? (y/n, default y): ");
    char compress_input[4];
    if (fgets(compress_input, sizeof(compress_input), stdin)) {
        config.use_compression = (compress_input[0] != 'n');
    }

    char* output = NULL;
    CryptoError err;
    if (strcmp(mode, "encrypt") == 0) {
        err = encrypt(message, key, &config, &output);
        if (err == CRYPTO_OK) {
            printf("Encrypted (base64): %s\n", output);
        }
    } else if (strcmp(mode, "decrypt") == 0) {
        err = decrypt(message, key, &config, &output);
        if (err == CRYPTO_OK) {
            printf("Decrypted: %s\n", output);
        }
    } else {
        printf("Invalid mode. Use 'encrypt' or 'decrypt'.\n");
        free(message);
        free(key);
        free(padding_input);
        return 1;
    }

    if (err != CRYPTO_OK) {
        printf("Error: %s\n", get_error_message(err));
    }

    free(output);
    free(message);
    free(key);
    free(padding_input);
    return err == CRYPTO_OK ? 0 : 1;
}
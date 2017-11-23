/*
 * DoIt shared header file.
 */

#define DOIT_PORT 17481

typedef struct doit_ctx_tag doit_ctx;

#define NONCE_MAX_LEN 64

/*
 * Set up a crypto context.
 */
doit_ctx *doit_init_ctx(void *secret, int secret_len);

/*
 * Free a crypto context.
 */
void doit_free_ctx(doit_ctx *ctx);

/*
 * Add perturbation data for nonce generation.
 */
void doit_perturb_nonce(doit_ctx *ctx, void *data, int len);

/*
 * Construct a nonce and return a ready-to-send buffer containing
 * it. Returns the length of the data to send. The buffer should be
 * freed after sending.
 */
void *doit_make_nonce(doit_ctx *ctx, int *output_len);

/*
 * Process incoming data on a DoIt connection. Buffers any plaintext
 * for later retrieval by doit_read. Returns a static error message
 * string if something bad happens (like a MAC failing). Otherwise,
 * returns NULL.
 */
const char *doit_incoming_data(doit_ctx *ctx, void *buf, int len);

/*
 * Return the current amount of buffered incoming plaintext.
 */
int doit_buffered(doit_ctx *ctx);

/*
 * Determine whether the incoming nonce has been received and the
 * keys have been set up.
 */
int doit_got_keys(doit_ctx *ctx);

/*
 * Read plaintext out of the buffered area. Returns the amount of
 * data actually read.
 */
int doit_read(doit_ctx *ctx, void *buf, int len);

/*
 * Construct a DoIt outgoing packet and return it in ready-to-send
 * form. The resulting packet should be freed after sending.
 */
void *doit_send(doit_ctx *ctx, void *buf, int len, int *output_len);

/*
 * Return the supported protocol version.
 */
unsigned doit_protocol_version(void);

/*
 * These come in handy in a couple of places.
 */

#define GET_32BIT_MSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[3]) | \
  ((unsigned long)(unsigned char)(cp)[2] << 8) | \
  ((unsigned long)(unsigned char)(cp)[1] << 16) | \
  ((unsigned long)(unsigned char)(cp)[0] << 24))

#define PUT_32BIT_MSB_FIRST(cp, value) do { \
  (cp)[3] = 0xFF & (value); \
  (cp)[2] = 0xFF & ((value) >> 8); \
  (cp)[1] = 0xFF & ((value) >> 16); \
  (cp)[0] = 0xFF & ((value) >> 24); } while (0)

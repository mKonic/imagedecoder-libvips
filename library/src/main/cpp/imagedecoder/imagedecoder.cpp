#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <string>
#include <vector>

#include <glib.h>
#include <jni.h>
#include <vips/vips8>

#include <webp/decode.h>

#include "exif.h"
#include "hdr.h"

using namespace vips;

/* ------------------------------------------------------------------ limits
 *
 * Each one turns an abort - glib's checked allocators die on failure - or an allocation sized
 * from an attacker-controlled header field into a DecodeException. */

/* Buffered whole, so the stream length is the first lever a hostile file has on the heap. */
static const size_t MAX_INPUT_BYTES = (size_t)512 * 1024 * 1024;

/* 268M pixels: past any real photograph, and pixels * 8 still fits a signed 32-bit size. */
static const guint64 MAX_PIXELS = (guint64)1 << 28;

/* A direct ByteBuffer is addressed by a jint, so this is a hard ceiling rather than a policy. */
static const guint64 MAX_OUTPUT_BYTES = (guint64)G_MAXINT;

/* A malformed n-pages otherwise multiplies straight into an allocation. */
static const int MAX_PAGES = 100000;

static const char* const EXC_DECODE = "ca/mpreg/imagedecoder/ImageDecoder$DecodeException";
static const char* const EXC_UNKNOWN_FORMAT =
  "ca/mpreg/imagedecoder/ImageDecoder$UnknownFormatException";
static const char* const EXC_OOM = "ca/mpreg/imagedecoder/ImageDecoder$OutOfMemoryException";

/* ------------------------------------------------------------------- errors */

/* Leaves exactly one pending exception, so callers can return unconditionally afterwards. */
static void
throw_decode_error(JNIEnv* env, const char* cls_name, const char* msg)
{
  if (env->ExceptionCheck())
    env->ExceptionClear();

  jclass cls = env->FindClass(cls_name);
  if (!cls) {
    /* FindClass left NoClassDefFoundError pending; that is the throw. */
    return;
  }
  env->ThrowNew(cls, msg && *msg ? msg : "Image decode failed");
  env->DeleteLocalRef(cls);
}

static void
throw_vips_error(JNIEnv* env, const vips::VError& e)
{
  std::string msg;
  try {
    const char* what = e.what();
    if (what)
      msg = what;
  } catch (...) {
    /* what() builds a std::string; a failure there must not escape. */
  }
  vips_error_clear();

  if (msg.empty())
    msg = "Image decode failed";

  const char* cls =
    msg.find("not in a known format") != std::string::npos ? EXC_UNKNOWN_FORMAT : EXC_DECODE;
  throw_decode_error(env, cls, msg.c_str());
}

/* Funnels every failure into the entry point's catch chain, which frees what the call owns. */
struct DecodeError
{
  const char* cls;
  std::string msg;

  DecodeError(const char* cls_, std::string msg_)
    : cls(cls_)
    , msg(std::move(msg_))
  {
  }
};

static void
fail(const char* cls, const std::string& msg)
{
  throw DecodeError(cls, msg);
}

static void
fail_oom(const std::string& what, guint64 bytes)
{
  char buf[64];
  g_snprintf(buf, sizeof(buf), " (%" G_GUINT64_FORMAT " bytes)", bytes);
  throw DecodeError(EXC_OOM, what + buf);
}

/* --------------------------------------------------------------- JNI lookup
 *
 * Both return null with an exception pending, and feeding that null back into JNI aborts the VM
 * rather than throwing. */

static jclass
find_class_checked(JNIEnv* env, const char* name)
{
  jclass cls = env->FindClass(name);
  if (!cls || env->ExceptionCheck()) {
    if (env->ExceptionCheck())
      env->ExceptionClear();
    fail(EXC_DECODE, std::string("Class not found: ") + name);
  }
  return cls;
}

static jmethodID
get_method_checked(JNIEnv* env, jclass cls, const char* name, const char* sig)
{
  jmethodID id = env->GetMethodID(cls, name, sig);
  if (!id || env->ExceptionCheck()) {
    if (env->ExceptionCheck())
      env->ExceptionClear();
    fail(EXC_DECODE, std::string("Method not found: ") + name);
  }
  return id;
}

/* The VM reclaims local refs only when the native frame returns, and a decode takes a dozen. */
struct LocalRef
{
  JNIEnv* env;
  jobject ref;

  LocalRef(JNIEnv* e, jobject r)
    : env(e)
    , ref(r)
  {
  }
  ~LocalRef()
  {
    if (ref)
      env->DeleteLocalRef(ref);
  }
  LocalRef(const LocalRef&) = delete;
  LocalRef& operator=(const LocalRef&) = delete;
};

/* vips_region_prepare fails deep inside the pipeline, and that throw used to skip the unref. */
struct RegionRef
{
  VipsRegion* region;

  explicit RegionRef(VipsRegion* r)
    : region(r)
  {
  }
  ~RegionRef()
  {
    if (region)
      g_object_unref(region);
  }
  RegionRef(const RegionRef&) = delete;
  RegionRef& operator=(const RegionRef&) = delete;
};

/* ---------------------------------------------------------------- lifecycle */

jint
JNI_OnLoad(JavaVM* vm, void*)
{
  JNIEnv* env;
  if (vm->GetEnv((void**)&env, JNI_VERSION_1_6) != JNI_OK)
    return JNI_ERR;

  /* Ignoring this left every later call on an uninitialised type system. */
  if (VIPS_INIT("VipsDecoder")) {
    vips_error_clear();
    return JNI_ERR;
  }

  vips_concurrency_set(1);

  /* One-shot pipelines never hit the operation cache; it only pins memory. */
  vips_cache_set_max(0);
  vips_cache_set_max_mem(0);
  vips_cache_set_max_files(0);

  return JNI_VERSION_1_6;
}

static jfieldID
ptr_field_id(JNIEnv* env, jobject obj)
{
  jclass cls = env->GetObjectClass(obj);
  if (!cls)
    return nullptr;
  jfieldID id = env->GetFieldID(cls, "ptr", "J");
  env->DeleteLocalRef(cls);
  if (!id && env->ExceptionCheck())
    env->ExceptionClear();
  return id;
}

static jlong
get_ptr(JNIEnv* env, jobject obj)
{
  jfieldID id = ptr_field_id(env, obj);
  return id ? env->GetLongField(obj, id) : 0;
}

/* Read and zero in one step, so a second free is a no-op instead of a double free. */
static jlong
take_ptr(JNIEnv* env, jobject obj)
{
  jfieldID id = ptr_field_id(env, obj);
  if (!id)
    return 0;
  jlong ptr = env->GetLongField(obj, id);
  env->SetLongField(obj, id, 0L);
  return ptr;
}

struct Decoder
{
  uint8_t* buffer;
  size_t buffer_size;
  int pages;
  int* durations;
  int durations_count;

  /* Decided once at header read: every page of an animation shares the container's signal. */
  int hdr_kind;

  /* Stops above SDR white the source reaches; understating it clips every highlight. */
  float hdr_headroom;

  /* For the PQ/HLG paths, straight from the container. */
  ColourSignal signal;

  /* Raw TIFF metadata for listTags/getTag: into [buffer] for a TIFF, else at [exif_owned], a copy
   * because the blob it came from dies with the VImage. */
  const uint8_t* exif_data;
  size_t exif_size;
  uint8_t* exif_owned;
};

static Decoder*
decoder_new()
{
  return g_try_new0(Decoder, 1);
}

static void
decoder_free(Decoder* d)
{
  if (!d)
    return;
  g_free(d->buffer);
  g_free(d->durations);
  g_free(d->exif_owned);
  g_free(d);
}

/* Null once free has run, so a call after close reports instead of dereferencing it. */
static Decoder*
decoder_for(JNIEnv* env, jobject obj)
{
  Decoder* d = reinterpret_cast<Decoder*>(get_ptr(env, obj));
  if (!d)
    fail(EXC_DECODE, "ImageDecoder has been closed");
  if (!d->buffer || d->buffer_size == 0)
    fail(EXC_DECODE, "ImageDecoder holds no image data");
  return d;
}

/* ---------------------------------------------------------------- stream in
 *
 * g_try_realloc rather than GByteArray, whose g_realloc aborts the process on failure. */
static uint8_t*
read_all(JNIEnv* env, jobject jstream, size_t* out_size, std::string* error)
{
  *out_size = 0;

  jclass cls = env->GetObjectClass(jstream);
  if (!cls) {
    *error = "Cannot resolve the InputStream class";
    return nullptr;
  }
  jmethodID read_method = env->GetMethodID(cls, "read", "([B)I");
  env->DeleteLocalRef(cls);
  if (!read_method) {
    if (env->ExceptionCheck())
      env->ExceptionClear();
    *error = "InputStream.read([B) not found";
    return nullptr;
  }

  const jint chunk = 64 * 1024;
  jbyteArray jbuf = env->NewByteArray(chunk);
  if (!jbuf || env->ExceptionCheck()) {
    if (env->ExceptionCheck())
      env->ExceptionClear();
    *error = "Out of memory allocating the read buffer";
    return nullptr;
  }
  LocalRef buf_ref(env, jbuf);

  uint8_t* data = nullptr;
  size_t len = 0;
  size_t cap = 0;

  while (true) {
    jint n = env->CallIntMethod(jstream, read_method, jbuf);

    /* Swallowing this handed the loader a truncated file to report as a corrupt one. */
    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      g_free(data);
      *error = "InputStream.read failed";
      return nullptr;
    }

    if (n <= 0)
      break;

    /* A stream lying about how much it wrote would otherwise drive an overread. */
    if (n > chunk) {
      g_free(data);
      *error = "InputStream.read returned more than the buffer length";
      return nullptr;
    }

    if ((guint64)len + (guint64)n > (guint64)MAX_INPUT_BYTES) {
      g_free(data);
      *error = "Out of memory: image exceeds the maximum input size";
      return nullptr;
    }

    if (len + (size_t)n > cap) {
      size_t want = cap ? cap * 2 : (size_t)chunk * 4;
      while (want < len + (size_t)n && want < MAX_INPUT_BYTES)
        want *= 2;
      if (want > MAX_INPUT_BYTES)
        want = MAX_INPUT_BYTES;

      uint8_t* grown = (uint8_t*)g_try_realloc(data, want);
      if (!grown) {
        g_free(data);
        *error = "Out of memory buffering the image";
        return nullptr;
      }
      data = grown;
      cap = want;
    }

    jbyte* bytes = env->GetByteArrayElements(jbuf, nullptr);
    if (!bytes) {
      if (env->ExceptionCheck())
        env->ExceptionClear();
      g_free(data);
      *error = "Out of memory reading the image";
      return nullptr;
    }
    memcpy(data + len, bytes, (size_t)n);
    env->ReleaseByteArrayElements(jbuf, bytes, JNI_ABORT);
    len += (size_t)n;
  }

  *out_size = len;
  return data;
}

/* By metadata, not vips_image_get_gainmap, which would decompress the map's JPEG. */
static bool
has_gainmap(vips::VImage& image)
{
  return image.get_typeof("gainmap") != 0 || image.get_typeof("gainmap-data") != 0;
}

/* Zero if the metadata is missing, which makes the image ordinary SDR to any caller. */
static float
gainmap_headroom(vips::VImage& image)
{
  if (image.get_typeof("gainmap-max-content-boost") == 0)
    return 0.0f;

  double* boost = nullptr;
  int n = 0;
  try {
    image.get_array_double("gainmap-max-content-boost", &boost, &n);
  } catch (const vips::VError&) {
    vips_error_clear();
    return 0.0f;
  }

  if (!boost || n <= 0)
    return 0.0f;

  double max_boost = 1.0;
  for (int i = 0; i < n; i++) {
    /* The caller sizes its display pipeline from this, and every compare against NaN is false. */
    if (std::isfinite(boost[i]))
      max_boost = VIPS_MAX(max_boost, boost[i]);
  }

  float stops = (float)log2(max_boost);
  return std::isfinite(stops) && stops > 0.0f ? stops : 0.0f;
}

/* A gainmap wins over a transfer function: an UltraHDR file is SDR base plus map. */
static void
detect_hdr(Decoder* decoder, vips::VImage& image)
{
  decoder->hdr_kind = HDR_NONE;
  decoder->hdr_headroom = 0.0f;
  decoder->signal.primaries = CICP_PRIMARIES_BT709;
  decoder->signal.transfer = CICP_TRANSFER_SRGB;

  if (has_gainmap(image)) {
    float headroom = gainmap_headroom(image);
    /* A map that cannot brighten is not worth a float buffer. */
    if (headroom > 0.0f) {
      decoder->hdr_kind = HDR_GAINMAP;
      decoder->hdr_headroom = headroom;
      return;
    }
  }

  /* Linear integer samples have no room above white and are just SDR. */
  const bool float_samples =
    image.format() == VIPS_FORMAT_FLOAT || image.format() == VIPS_FORMAT_DOUBLE;

  ColourSignal signal;
  float peak_nits = 0.0f;
  if (hdr_find_colour_signal(decoder->buffer, decoder->buffer_size, &signal, &peak_nits)) {
    int kind = hdr_kind_for_transfer(signal.transfer);

    /* Only JXL declares a linear transfer, and always with float samples. */
    if (kind == HDR_NONE && signal.transfer == CICP_TRANSFER_LINEAR && float_samples)
      kind = HDR_LINEAR;

    if (kind != HDR_NONE) {
      decoder->hdr_kind = kind;
      decoder->signal = signal;

      /* A container is free to declare a garbage peak. */
      if (!std::isfinite(peak_nits) || peak_nits <= 0.0f)
        peak_nits = 0.0f;

      /* A declared peak beats the nominal one; used only to tone map when HDR can't present. */
      float headroom = peak_nits > HDR_SDR_WHITE_NITS ? (float)log2(peak_nits / HDR_SDR_WHITE_NITS)
                       : kind == HDR_PQ ? (float)log2(10000.0 / HDR_SDR_WHITE_NITS)
                                        : (float)log2(HDR_HLG_PEAK_NITS / HDR_SDR_WHITE_NITS);
      decoder->hdr_headroom = std::isfinite(headroom) && headroom > 0.0f ? headroom : 0.0f;
      return;
    }
  }

  /* A loader that already handed us linear scRGB - libvips does this for a few
   * genuinely floating-point formats. No transfer function to undo. */
  if (image.interpretation() == VIPS_INTERPRETATION_scRGB) {
    decoder->hdr_kind = HDR_LINEAR;
    /* Nothing declares a peak, so claim the range half-float can carry. */
    decoder->hdr_headroom = 4.0f;
  }
}

/* Header fields, so attacker-controlled: checked before anything sizes a buffer from them. */
static void
check_dimensions(int width, int height)
{
  if (width <= 0 || height <= 0)
    fail(EXC_DECODE, "Image has no pixels");

  if ((guint64)width * (guint64)height > MAX_PIXELS)
    fail(EXC_OOM, "Image exceeds the maximum supported pixel count");
}

/* Multiplied wide: size_t is 32 bits on the 32-bit ABIs, where the product wraps to a small
 * allocation the write then overruns. */
static size_t
checked_buffer_size(guint64 pixels, guint64 bytes_per_pixel)
{
  if (pixels == 0 || bytes_per_pixel == 0)
    fail(EXC_DECODE, "Image has no pixels");

  guint64 total = pixels * bytes_per_pixel;
  if (total / pixels != bytes_per_pixel)
    fail_oom("Pixel buffer size overflows", MAX_OUTPUT_BYTES);
  if (total > MAX_OUTPUT_BYTES || total > (guint64)SIZE_MAX)
    fail_oom("Pixel buffer exceeds the maximum direct buffer size", total);

  return (size_t)total;
}

/* Converts the VM's OutOfMemoryError: the caller can handle a DecodeException, where an Error
 * unwinds past every handler it has. */
static jobject
allocate_direct(JNIEnv* env, size_t size, void** out_data)
{
  if ((guint64)size > MAX_OUTPUT_BYTES)
    fail_oom("Buffer exceeds the maximum direct buffer size", (guint64)size);

  jclass cls = find_class_checked(env, "java/nio/ByteBuffer");
  LocalRef cls_ref(env, cls);

  jmethodID allocate = env->GetStaticMethodID(cls, "allocateDirect", "(I)Ljava/nio/ByteBuffer;");
  if (!allocate || env->ExceptionCheck()) {
    if (env->ExceptionCheck())
      env->ExceptionClear();
    fail(EXC_DECODE, "ByteBuffer.allocateDirect not found");
  }

  jobject buffer = env->CallStaticObjectMethod(cls, allocate, (jint)size);
  if (env->ExceptionCheck() || !buffer) {
    if (env->ExceptionCheck())
      env->ExceptionClear();
    if (buffer)
      env->DeleteLocalRef(buffer);
    fail_oom("Out of memory allocating the pixel buffer", (guint64)size);
  }

  void* data = env->GetDirectBufferAddress(buffer);
  if (!data) {
    env->DeleteLocalRef(buffer);
    if (env->ExceptionCheck())
      env->ExceptionClear();
    fail(EXC_DECODE, "Failed to map the direct byte buffer");
  }

  *out_data = data;
  return buffer;
}

static jobject
decoder_object(JNIEnv* env, Decoder* decoder);

extern "C" JNIEXPORT jobject JNICALL
Java_ca_mpreg_imagedecoder_ImageDecoder_nativeNew(JNIEnv* env, jclass, jobject jstream)
{
  if (!jstream) {
    throw_decode_error(env, EXC_DECODE, "Input stream is null");
    return nullptr;
  }

  Decoder* decoder = decoder_new();
  if (!decoder) {
    throw_decode_error(env, EXC_OOM, "Out of memory creating the decoder");
    return nullptr;
  }

  std::string read_error;
  decoder->buffer = read_all(env, jstream, &decoder->buffer_size, &read_error);

  if (!decoder->buffer || decoder->buffer_size == 0) {
    decoder_free(decoder);
    const bool oom = read_error.compare(0, 13, "Out of memory") == 0;
    throw_decode_error(env, oom ? EXC_OOM : EXC_DECODE,
                       read_error.empty() ? "Empty or unreadable image stream"
                                          : read_error.c_str());
    return nullptr;
  }

  return decoder_object(env, decoder);
}

/* Parses [decoder]'s buffer and wraps it in an ImageDecoder, which then owns it. Frees it and
 * leaves an exception pending on failure. */
static jobject
decoder_object(JNIEnv* env, Decoder* decoder)
{
  try {
    vips::VImage image = vips::VImage::new_from_buffer(decoder->buffer, decoder->buffer_size, "");

    check_dimensions(image.width(), image.height());

    int pages = image.get_typeof(VIPS_META_N_PAGES) != 0 ? image.get_int(VIPS_META_N_PAGES) : 1;
    /* A corrupt n-pages of 0 divided by zero in decodeNext; a negative one indexed backwards. */
    decoder->pages = CLAMP(pages, 1, MAX_PAGES);

    if (image.get_typeof("delay") != 0) {
      int* delays = nullptr;
      int n = 0;

      image.get_array_int("delay", &delays, &n);
      if (delays && n > 0) {
        n = VIPS_MIN(n, MAX_PAGES);
        decoder->durations = g_try_new(int, n);
        if (!decoder->durations)
          fail_oom("Out of memory reading the frame durations", (guint64)n * sizeof(int));
        decoder->durations_count = n;
        memcpy(decoder->durations, delays, (size_t)n * sizeof(int));
      }
    }

    detect_hdr(decoder, image);
    const bool is_hdr = decoder->hdr_kind != HDR_NONE;

    const char* loader_cstr =
      image.get_typeof("vips-loader") != 0 ? image.get_string("vips-loader") : "";
    std::string loader_str = loader_cstr ? loader_cstr : "";

    decoder->exif_owned = exif_bytes(image, decoder->buffer, decoder->buffer_size,
                                     &decoder->exif_data, &decoder->exif_size);

    image = vips::VImage();

    jstring jloader = env->NewStringUTF(loader_str.c_str());
    if (!jloader || env->ExceptionCheck()) {
      if (env->ExceptionCheck())
        env->ExceptionClear();
      fail(EXC_OOM, "Out of memory creating the loader name");
    }
    LocalRef loader_ref(env, jloader);

    jclass cls = find_class_checked(env, "ca/mpreg/imagedecoder/ImageDecoder");
    LocalRef cls_ref(env, cls);
    jmethodID ctor = get_method_checked(env, cls, "<init>", "(JIIZIFLjava/lang/String;)V");

    jobject result =
      env->NewObject(cls, ctor, reinterpret_cast<jlong>(decoder), decoder->pages, 0,
                     (jboolean)is_hdr, decoder->hdr_kind, decoder->hdr_headroom, jloader);
    if (!result || env->ExceptionCheck()) {
      /* Ownership never reached Kotlin, so nothing else will ever free this. */
      if (env->ExceptionCheck())
        env->ExceptionClear();
      if (result)
        env->DeleteLocalRef(result);
      fail(EXC_OOM, "Out of memory creating the decoder object");
    }

    return result;
  } catch (const DecodeError& e) {
    decoder_free(decoder);
    throw_decode_error(env, e.cls, e.msg.c_str());
    return nullptr;
  } catch (const vips::VError& e) {
    decoder_free(decoder);
    throw_vips_error(env, e);
    return nullptr;
  } catch (const std::bad_alloc&) {
    decoder_free(decoder);
    vips_error_clear();
    throw_decode_error(env, EXC_OOM, "Out of memory reading the image header");
    return nullptr;
  } catch (...) {
    decoder_free(decoder);
    vips_error_clear();
    throw_decode_error(env, EXC_DECODE, "Unknown error reading the image header");
    return nullptr;
  }
}

/* Released however this returns, a throw from the walk included. */
struct Utf8Chars
{
  JNIEnv* env;
  jstring owner;
  const char* chars;

  ~Utf8Chars()
  {
    if (chars)
      env->ReleaseStringUTFChars(owner, chars);
  }
};

extern "C" JNIEXPORT jobjectArray JNICALL
Java_ca_mpreg_imagedecoder_ImageDecoder_nativeListTags(JNIEnv* env, jobject obj)
{
  try {
    Decoder* decoder = decoder_for(env, obj);
    jobjectArray tags = exif_list_tags(env, decoder->exif_data, decoder->exif_size);

    /* Null with no pending exception means the VM refused an allocation. */
    if (!tags && !env->ExceptionCheck())
      fail(EXC_OOM, "Out of memory listing the tags");

    return tags;
  } catch (const DecodeError& e) {
    throw_decode_error(env, e.cls, e.msg.c_str());
    return nullptr;
  } catch (const std::bad_alloc&) {
    throw_decode_error(env, EXC_OOM, "Out of memory listing the tags");
    return nullptr;
  } catch (...) {
    throw_decode_error(env, EXC_DECODE, "Unknown error listing the tags");
    return nullptr;
  }
}

extern "C" JNIEXPORT jstring JNICALL
Java_ca_mpreg_imagedecoder_ImageDecoder_nativeGetTag(JNIEnv* env, jobject obj, jstring jname)
{
  try {
    Decoder* decoder = decoder_for(env, obj);
    if (!decoder->exif_data || !jname)
      return nullptr;

    Utf8Chars name = { env, jname, env->GetStringUTFChars(jname, nullptr) };
    if (!name.chars) {
      if (env->ExceptionCheck())
        env->ExceptionClear();
      fail(EXC_OOM, "Out of memory reading the tag name");
    }

    return exif_get_tag(env, decoder->exif_data, decoder->exif_size, name.chars);
  } catch (const DecodeError& e) {
    throw_decode_error(env, e.cls, e.msg.c_str());
    return nullptr;
  } catch (const std::bad_alloc&) {
    throw_decode_error(env, EXC_OOM, "Out of memory reading the tag");
    return nullptr;
  } catch (...) {
    throw_decode_error(env, EXC_DECODE, "Unknown error reading the tag");
    return nullptr;
  }
}

extern "C" JNIEXPORT void JNICALL
Java_ca_mpreg_imagedecoder_ImageDecoder_nativeFree(JNIEnv* env, jobject obj)
{
  /* take, not get: leaving the pointer in place let the finalizer free the block a second
   * time, and a decode after close read it. */
  decoder_free(reinterpret_cast<Decoder*>(take_ptr(env, obj)));
}

/* The value a full-scale sample holds in [frame]'s band format. */
static double
sample_max(vips::VImage& frame)
{
  switch (frame.format()) {
    case VIPS_FORMAT_UCHAR:
      return 255.0;
    case VIPS_FORMAT_USHORT:
      return 65535.0;
    default:
      /* Float and friends are normalised already. */
      return 1.0;
  }
}

/* Three entries always, even for a mono map, which simply repeats. Missing metadata gives the
 * identity, so a malformed file degrades to the base image rather than to a wrong one. */
static jfloatArray
gainmap_metadata_array(JNIEnv* env, vips::VImage& image, const char* field, float identity)
{
  float values[3] = { identity, identity, identity };

  if (image.get_typeof(field) != 0) {
    try {
      double* d = nullptr;
      int n = 0;
      image.get_array_double(field, &d, &n);
      /* An empty array indexed d[-1]. */
      if (d && n > 0) {
        for (int i = 0; i < 3; i++) {
          double v = d[VIPS_MIN(i, n - 1)];
          if (std::isfinite(v))
            values[i] = (float)v;
        }
      }
    } catch (const vips::VError&) {
      vips_error_clear();
    }
  }

  jfloatArray arr = env->NewFloatArray(3);
  if (!arr || env->ExceptionCheck()) {
    if (env->ExceptionCheck())
      env->ExceptionClear();
    return nullptr;
  }
  env->SetFloatArrayRegion(arr, 0, 3, values);
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
    env->DeleteLocalRef(arr);
    return nullptr;
  }
  return arr;
}

/* Handed over unapplied for the viewer to combine: applying the gain is a display decision, and
 * libvips's own uhdr2scRGB gets three-channel maps wrong anyway - it runs the map through the
 * sRGB EOTF where libultrahdr's applyGain uses the raw value.
 *
 * Null on any failure: a missing gainmap costs the caller its HDR, a failed decode the picture. */
static jobject
build_gainmap(JNIEnv* env, vips::VImage& image)
{
  VipsImage* raw = vips_image_get_gainmap(image.get_image());
  if (!raw) {
    vips_error_clear();
    return nullptr;
  }

  /* VImage takes the reference get_gainmap returned, down every throw path below too. */
  vips::VImage map(raw);

  jobject buffer = nullptr;
  jfloatArray gamma = nullptr;
  jfloatArray min_boost = nullptr;
  jfloatArray max_boost = nullptr;
  jfloatArray offset_sdr = nullptr;
  jfloatArray offset_hdr = nullptr;
  jobject result = nullptr;

  try {
    /* uchar, however the map's JPEG was coded. */
    if (map.format() != VIPS_FORMAT_UCHAR)
      map = map.cast(VIPS_FORMAT_UCHAR);

    /* One or three bands - anything else is not a gainmap we understand. */
    if (map.bands() == 2)
      map = map.extract_band(0);
    else if (map.bands() > 3)
      map = map.extract_band(0, vips::VImage::option()->set("n", 3));

    const int width = map.width();
    const int height = map.height();
    const int bands = map.bands();

    if (width <= 0 || height <= 0 || bands <= 0)
      fail(EXC_DECODE, "Gainmap has no pixels");
    if ((guint64)width * (guint64)height > MAX_PIXELS)
      fail(EXC_OOM, "Gainmap exceeds the maximum supported pixel count");

    const size_t size = checked_buffer_size((guint64)width * (guint64)height, (guint64)bands);

    void* data = nullptr;
    buffer = allocate_direct(env, size, &data);

    map.write(vips::VImage::new_from_memory(data, size, width, height, bands, VIPS_FORMAT_UCHAR));

    gamma = gainmap_metadata_array(env, image, "gainmap-gamma", 1.0f);
    min_boost = gainmap_metadata_array(env, image, "gainmap-min-content-boost", 1.0f);
    max_boost = gainmap_metadata_array(env, image, "gainmap-max-content-boost", 1.0f);
    offset_sdr = gainmap_metadata_array(env, image, "gainmap-offset-sdr", 0.0f);
    offset_hdr = gainmap_metadata_array(env, image, "gainmap-offset-hdr", 0.0f);

    /* The Kotlin constructor declares these non-null. */
    if (!gamma || !min_boost || !max_boost || !offset_sdr || !offset_hdr)
      fail(EXC_OOM, "Out of memory reading the gainmap metadata");

    jclass cls = find_class_checked(env, "ca/mpreg/imagedecoder/ImageDecoder$Gainmap");
    LocalRef cls_ref(env, cls);
    jmethodID ctor =
      get_method_checked(env, cls, "<init>", "(Ljava/nio/ByteBuffer;III[F[F[F[F[F)V");

    result = env->NewObject(cls, ctor, buffer, width, height, bands, gamma, min_boost, max_boost,
                            offset_sdr, offset_hdr);
    if (env->ExceptionCheck()) {
      env->ExceptionClear();
      if (result)
        env->DeleteLocalRef(result);
      result = nullptr;
    }
  } catch (...) {
    vips_error_clear();
    if (env->ExceptionCheck())
      env->ExceptionClear();
    result = nullptr;
  }

  if (buffer)
    env->DeleteLocalRef(buffer);
  if (gamma)
    env->DeleteLocalRef(gamma);
  if (min_boost)
    env->DeleteLocalRef(min_boost);
  if (max_boost)
    env->DeleteLocalRef(max_boost);
  if (offset_sdr)
    env->DeleteLocalRef(offset_sdr);
  if (offset_hdr)
    env->DeleteLocalRef(offset_hdr);

  return result;
}

/* An UltraHDR JPEG's base is usually Display P3, and the embedded profile is the only place that
 * is written down. Treating those values as sRGB skews the whole SDR part of the picture.
 *
 * A file with no profile is left alone. PQ and HLG do not come through here - their primaries
 * are signalled in the container and handled by the matrix in the pixel loop. */
static vips::VImage
to_srgb_primaries(vips::VImage frame)
{
  if (frame.get_typeof(VIPS_META_ICC_NAME) == 0)
    return frame;

  try {
    /* Relative colorimetric: perceptual would add lcms's own gamut compression. depth pinned -
     * it follows the input otherwise, leaving the 8-bit path holding ushort reported as RGBA8. */
    return frame.icc_transform("srgb", vips::VImage::option()
                                         ->set("embedded", true)
                                         ->set("intent", VIPS_INTENT_RELATIVE)
                                         ->set("depth", 8));
  } catch (const vips::VError&) {
    /* A profile lcms cannot load is not worth failing the decode over. */
    vips_error_clear();
    return frame;
  }
}

/* Four float bands, so the pixel loop varies only by transfer function. The colour bands hold
 * whatever that loop's EOTF expects - the raw signal in [0, 1] for PQ and HLG, linear light
 * otherwise - and alpha always [0, 1]. */
static vips::VImage
prepare_hdr(Decoder* decoder, vips::VImage frame)
{
  /* Gainmaps never reach here: their base leaves through the plain 8-bit path. */
  double max = sample_max(frame);

  if (frame.bands() < 1)
    fail(EXC_DECODE, "Image has no bands");

  /* Grey to RGB first: the alpha bandjoin would leave two bands and the pixel loop reads four. */
  if (frame.bands() < 3) {
    vips::VImage grey = frame.extract_band(0);
    vips::VImage rgb = grey.bandjoin(std::vector<vips::VImage>{ grey, grey });
    frame = frame.bands() == 2 ? rgb.bandjoin(frame.extract_band(1)) : rgb;
  }

  if (frame.bands() < 4)
    frame = frame.bandjoin(max);
  else if (frame.bands() > 4)
    frame = frame.extract_band(0, vips::VImage::option()->set("n", 4));

  return frame.cast(VIPS_FORMAT_FLOAT).linear(1.0 / max, 0.0);
}

/* Into tightly packed RGBA half-float at [out], which must hold exactly [out_samples] uint16s.
 *
 * Extended sRGB, so an SDR pixel is numerically identical to what the 8-bit path would have
 * produced and nothing downstream has to know which it got. */
static void
write_hdr_pixels(Decoder* decoder, vips::VImage frame, uint16_t* out, size_t out_samples)
{
  const int width = frame.width();
  const int height = frame.height();
  const int kind = decoder->hdr_kind;

  /* The loop below steps four float bands per pixel, which prepare_hdr guarantees. */
  if (frame.bands() != 4 || frame.format() != VIPS_FORMAT_FLOAT)
    fail(EXC_DECODE, "write_hdr_pixels needs four float bands");

  check_dimensions(width, height);

  /* The caller sized [out] itself; a resize anywhere between would overrun a direct buffer. */
  if ((guint64)width * (guint64)height * 4 != (guint64)out_samples)
    fail(EXC_DECODE, "Pixel buffer does not match the image dimensions");

  /* Kinds with no signalled primaries default to BT.709, so the matrix comes back null - they
   * are ICC-converted before the frame gets here. */
  const float* matrix = hdr_matrix_to_srgb(decoder->signal.primaries);

  /* A strip at a time: a whole-image float copy would cost six more bytes per pixel. */
  const int strip = 64;

  RegionRef region(vips_region_new(frame.get_image()));
  if (!region.region)
    fail(EXC_OOM, "Out of memory creating the pixel region");

  for (int y = 0; y < height; y += strip) {
    VipsRect r;
    r.left = 0;
    r.top = y;
    r.width = width;
    r.height = VIPS_MIN(strip, height - y);

    /* RegionRef unrefs through the throw this can raise several frames down. */
    if (vips_region_prepare(region.region, &r))
      throw vips::VError();

    for (int i = 0; i < r.height; i++) {
      const float* p = (const float*)VIPS_REGION_ADDR(region.region, 0, y + i);
      if (!p)
        fail(EXC_DECODE, "Region address out of bounds");

      uint16_t* q = out + (size_t)(y + i) * (size_t)width * 4;

      for (int x = 0; x < width; x++) {
        float rgb[3] = { p[0], p[1], p[2] };
        float alpha = p[3];
        p += 4;

        switch (kind) {
          case HDR_PQ:
            rgb[0] = hdr_pq_eotf(rgb[0]);
            rgb[1] = hdr_pq_eotf(rgb[1]);
            rgb[2] = hdr_pq_eotf(rgb[2]);
            break;

          case HDR_HLG:
            rgb[0] = hdr_hlg_inverse_oetf(rgb[0]);
            rgb[1] = hdr_hlg_inverse_oetf(rgb[1]);
            rgb[2] = hdr_hlg_inverse_oetf(rgb[2]);
            hdr_hlg_ootf(rgb);
            break;

          default:
            /* Gainmap and scRGB arrive as linear light already. */
            break;
        }

        if (matrix)
          hdr_apply_matrix(matrix, rgb);

        q[0] = hdr_encode_half(rgb[0]);
        q[1] = hdr_encode_half(rgb[1]);
        q[2] = hdr_encode_half(rgb[2]);
        q[3] = hdr_encode_alpha(alpha);
        q += 4;
      }
    }
  }
}

/* The gainmap has to rotate with the base, or the two disagree on which way is up. */
static vips::VImage
apply_orientation(vips::VImage frame)
{
  if (frame.get_typeof(VIPS_META_ORIENTATION) == 0)
    return frame;

  int orientation = frame.get_int(VIPS_META_ORIENTATION);
  frame = frame.copy_memory().autorot();

  VipsImage* gainmap = vips_image_get_gainmap(frame.get_image());
  if (!gainmap) {
    vips_error_clear();
    return frame;
  }

  vips_image_set_int(gainmap, VIPS_META_ORIENTATION, orientation);

  VipsImage* rotated = nullptr;
  if (!vips_autorot(gainmap, &rotated, nullptr) && rotated) {
    vips_image_set_image(frame.get_image(), "gainmap", rotated);
    g_object_unref(rotated);
  } else {
    /* Leaving the map unrotated is wrong but recoverable; failing the decode is not. */
    vips_error_clear();
  }
  g_object_unref(gainmap);

  return frame;
}

extern "C" JNIEXPORT jobject JNICALL
Java_ca_mpreg_imagedecoder_ImageDecoder_nativeDecode(JNIEnv* env, jobject obj, jint page,
                                                     jboolean crop, jboolean getTrim)
{
  jobject jgainmap = nullptr;
  jobject byteBuffer = nullptr;
  jobject result = nullptr;
  const char* err_cls = nullptr;
  std::string err_msg;

  try {
    Decoder* decoder = decoder_for(env, obj);

    if (page < 0 || page >= decoder->pages)
      fail(EXC_DECODE, "Page index out of range");

    vips::VImage frame = vips::VImage::new_from_buffer(
      decoder->buffer, decoder->buffer_size, "",
      vips::VImage::option()
        ->set("access", (crop || getTrim) ? VIPS_ACCESS_RANDOM : VIPS_ACCESS_SEQUENTIAL)
        ->set("page", page));

    check_dimensions(frame.width(), frame.height());

    frame = apply_orientation(frame);

    /* A gainmap's base is 8-bit sRGB; only the transfer-function paths hand back float. */
    const bool float_out = decoder->hdr_kind == HDR_PQ || decoder->hdr_kind == HDR_HLG ||
                           decoder->hdr_kind == HDR_LINEAR;

    /* Before anything else touches the image: vips metadata rides along by convention, so an
     * ICC transform dropping the gainmap fields would lose the HDR silently. The map is a
     * multiplier, not colour, so it wants no colour management of its own. */
    if (decoder->hdr_kind == HDR_GAINMAP)
      jgainmap = build_gainmap(env, frame);

    /* Container-signalled primaries go through the matrix in the pixel loop; an ICC profile -
     * the only place a plain Display P3 JPEG says so - goes through lcms here. */
    if (decoder->hdr_kind == HDR_NONE || decoder->hdr_kind == HDR_GAINMAP)
      frame = to_srgb_primaries(frame);

    /* find_trim matches in 8-bit sRGB, so trimming measures an SDR rendition even when the
     * pixels handed back are HDR. Both views come off the same load. */
    vips::VImage trim_frame = frame;
    if (trim_frame.interpretation() != VIPS_INTERPRETATION_sRGB &&
        trim_frame.interpretation() != VIPS_INTERPRETATION_scRGB)
      trim_frame = trim_frame.colourspace(VIPS_INTERPRETATION_sRGB);

    if (float_out) {
      frame = prepare_hdr(decoder, frame);
    } else {
      frame = trim_frame;

      if (frame.bands() < 4)
        frame = frame.bandjoin(255);
      if (frame.bands() > 4)
        frame = frame.extract_band(0, vips::VImage::option()->set("n", 4));
    }

    const int full_width = frame.width();
    const int full_height = frame.height();
    check_dimensions(full_width, full_height);

    int width = full_width;
    int height = full_height;

    int duration = 0;
    if (decoder->durations && page < decoder->durations_count)
      duration = decoder->durations[page];
    /* A negative delay from a corrupt header runs an animation backwards forever. */
    if (duration < 0)
      duration = 0;

    int trim_left = 0;
    int trim_top = 0;
    int trim_width = 0;
    int trim_height = 0;

    if (crop || getTrim) {
      int trim_top_w = 0, trim_width_w = 0, trim_height_w = 0;
      int trim_left_w = trim_frame.find_trim(&trim_top_w, &trim_width_w, &trim_height_w,
                                             vips::VImage::option()->set("line_art", true));

      int trim_top_b = 0, trim_width_b = 0, trim_height_b = 0;
      int trim_left_b =
        trim_frame.find_trim(&trim_top_b, &trim_width_b, &trim_height_b,
                             vips::VImage::option()->set("line_art", true)->set("background", 0.0));

      trim_left = std::max(trim_left_w, trim_left_b);
      trim_top = std::max(trim_top_w, trim_top_b);
      trim_width = std::min(trim_width_w, trim_width_b);
      trim_height = std::min(trim_height_w, trim_height_b);

      /* An all-background image trims to an empty rect, and combining two independent runs can
       * push it past the edge. Either one reaching crop failed the whole decode. */
      trim_left = CLAMP(trim_left, 0, full_width - 1);
      trim_top = CLAMP(trim_top, 0, full_height - 1);
      trim_width = CLAMP(trim_width, 0, full_width - trim_left);
      trim_height = CLAMP(trim_height, 0, full_height - trim_top);

      if (trim_width <= 0 || trim_height <= 0) {
        trim_left = 0;
        trim_top = 0;
        trim_width = full_width;
        trim_height = full_height;
      }
    }

    if (crop) {
      frame = frame.crop(trim_left, trim_top, trim_width, trim_height);
      width = trim_width;
      height = trim_height;
      trim_left = 0;
      trim_top = 0;
      trim_width = 0;
      trim_height = 0;
    }

    /* From the image about to be written, not the dimensions reported before the crop. */
    check_dimensions(frame.width(), frame.height());
    if (frame.width() != width || frame.height() != height)
      fail(EXC_DECODE, "Image dimensions changed unexpectedly");

    const int pixel_format = float_out ? PIXFMT_RGBA16F : PIXFMT_RGBA8;
    const guint64 pixels = (guint64)width * (guint64)height;

    /* Four float bands in, half-float out, so the HDR buffer is half what the vips image says. */
    const size_t size =
      float_out ? checked_buffer_size(pixels, 4 * sizeof(uint16_t))
                : checked_buffer_size(pixels, (guint64)VIPS_IMAGE_SIZEOF_PEL(frame.get_image()));

    void* data = nullptr;
    byteBuffer = allocate_direct(env, size, &data);

    if (float_out)
      write_hdr_pixels(decoder, frame, (uint16_t*)data, size / sizeof(uint16_t));
    else
      frame.write(vips::VImage::new_from_memory(data, size, frame.width(), frame.height(),
                                                frame.bands(), frame.format()));

    jclass cls = find_class_checked(env, "ca/mpreg/imagedecoder/ImageDecoder$DecodeResult");
    LocalRef cls_ref(env, cls);
    jmethodID ctor = get_method_checked(
      env, cls, "<init>",
      "(Ljava/nio/ByteBuffer;IIIIIIIIFLca/mpreg/imagedecoder/ImageDecoder$Gainmap;)V");

    result = env->NewObject(cls, ctor, byteBuffer, width, height, duration, trim_left, trim_top,
                            trim_width, trim_height, pixel_format, decoder->hdr_headroom, jgainmap);
    if (!result || env->ExceptionCheck()) {
      if (env->ExceptionCheck())
        env->ExceptionClear();
      if (result)
        env->DeleteLocalRef(result);
      result = nullptr;
      fail(EXC_OOM, "Out of memory creating the decode result");
    }
  } catch (const DecodeError& e) {
    err_cls = e.cls;
    err_msg = e.msg;
  } catch (const vips::VError& e) {
    /* Formatted here so the refs below are released either way. */
    err_cls = nullptr;
    if (byteBuffer)
      env->DeleteLocalRef(byteBuffer);
    if (jgainmap)
      env->DeleteLocalRef(jgainmap);
    throw_vips_error(env, e);
    return nullptr;
  } catch (const std::bad_alloc&) {
    err_cls = EXC_OOM;
    err_msg = "Out of memory decoding the image";
  } catch (...) {
    err_cls = EXC_DECODE;
    err_msg = "Unknown error decoding the image";
  }

  if (byteBuffer)
    env->DeleteLocalRef(byteBuffer);
  if (jgainmap)
    env->DeleteLocalRef(jgainmap);

  if (err_cls) {
    vips_error_clear();
    throw_decode_error(env, err_cls, err_msg.c_str());
    return nullptr;
  }

  return result;
}

extern "C" JNIEXPORT jobject JNICALL
Java_ca_mpreg_imagedecoder_ImageDecoder_nativeEncode(JNIEnv* env, jobject obj, jstring jsuffix,
                                                     jint page)
{
  if (!jsuffix) {
    throw_decode_error(env, EXC_DECODE, "Encode suffix is null");
    return nullptr;
  }

  const char* suffix = env->GetStringUTFChars(jsuffix, nullptr);
  if (!suffix) {
    if (env->ExceptionCheck())
      env->ExceptionClear();
    throw_decode_error(env, EXC_OOM, "Out of memory reading the encode suffix");
    return nullptr;
  }

  /* write_to_buffer hands over g_malloc'd bytes; every path must transfer or free them. */
  void* data = nullptr;
  size_t size = 0;
  jobject byteBuffer = nullptr;
  jobject result = nullptr;
  const char* err_cls = nullptr;
  std::string err_msg;
  bool vips_thrown = false;

  try {
    Decoder* decoder = decoder_for(env, obj);

    /* -1 is libvips's "every page"; anything else has to name a real one. */
    if (page < -1 || page >= decoder->pages)
      fail(EXC_DECODE, "Page index out of range");

    vips::VImage frame = vips::VImage::new_from_buffer(decoder->buffer, decoder->buffer_size, "",
                                                       vips::VImage::option()->set("page", page));

    check_dimensions(frame.width(), frame.height());

    frame = apply_orientation(frame);

    frame.write_to_buffer(suffix, &data, &size);

    if (!data || size == 0)
      fail(EXC_DECODE, "Encoder produced no data");
    if ((guint64)size > MAX_OUTPUT_BYTES)
      fail_oom("Encoded image exceeds the maximum direct buffer size", (guint64)size);

    byteBuffer = env->NewDirectByteBuffer(data, (jlong)size);
    if (!byteBuffer || env->ExceptionCheck()) {
      if (env->ExceptionCheck())
        env->ExceptionClear();
      fail(EXC_OOM, "Failed to allocate the direct byte buffer");
    }

    jclass cls = find_class_checked(env, "ca/mpreg/imagedecoder/ImageDecoder$EncodeResult");
    LocalRef cls_ref(env, cls);
    jmethodID ctor = get_method_checked(env, cls, "<init>", "(JLjava/nio/ByteBuffer;)V");

    result = env->NewObject(cls, ctor, (jlong)(intptr_t)data, byteBuffer);
    if (!result || env->ExceptionCheck()) {
      if (env->ExceptionCheck())
        env->ExceptionClear();
      if (result)
        env->DeleteLocalRef(result);
      result = nullptr;
      /* Nothing took the buffer, so this call still owns it. */
      fail(EXC_OOM, "Out of memory creating the encode result");
    }

    /* Ownership of [data] now sits in the EncodeResult. */
    data = nullptr;
  } catch (const DecodeError& e) {
    err_cls = e.cls;
    err_msg = e.msg;
  } catch (const vips::VError& e) {
    vips_thrown = true;
    env->ReleaseStringUTFChars(jsuffix, suffix);
    suffix = nullptr;
    if (byteBuffer)
      env->DeleteLocalRef(byteBuffer);
    byteBuffer = nullptr;
    g_free(data);
    data = nullptr;
    throw_vips_error(env, e);
  } catch (const std::bad_alloc&) {
    err_cls = EXC_OOM;
    err_msg = "Out of memory encoding the image";
  } catch (...) {
    err_cls = EXC_DECODE;
    err_msg = "Unknown error encoding the image";
  }

  if (suffix)
    env->ReleaseStringUTFChars(jsuffix, suffix);
  if (byteBuffer)
    env->DeleteLocalRef(byteBuffer);
  g_free(data);

  if (vips_thrown)
    return nullptr;

  if (err_cls) {
    vips_error_clear();
    throw_decode_error(env, err_cls, err_msg.c_str());
    return nullptr;
  }

  return result;
}

extern "C" JNIEXPORT void JNICALL
Java_ca_mpreg_imagedecoder_ImageDecoder_00024EncodeResult_nativeFree(JNIEnv* env, jobject obj)
{
  jlong ptr = take_ptr(env, obj);
  if (ptr == 0)
    return;
  g_free((void*)(intptr_t)ptr);
}

/* ------------------------------------------------------------ row decoding
 *
 * A still image decoded top to bottom while its bytes are still arriving. libvips reads the
 * stream through a custom source only as far as the rows asked for need, so a baseline JPEG or
 * a non-interlaced PNG hands its first rows back long before the file has finished downloading.
 * Anything that cannot come out that way is read to the end and handed back as an ImageDecoder. */

static const jint ROW_CHUNK = 64 * 1024;

struct RowStream
{
  /* Of the JNI call in progress: the read callback only ever runs inside one. */
  JNIEnv* env;
  jobject stream;
  jmethodID read;
  jbyteArray chunk;
  bool failed;
  guint64 total;

  /* Every byte read so far, while a whole-file decode may still need them. */
  bool tee;
  uint8_t* data;
  size_t len;
  size_t cap;

  /* While set, reads hand back the tee from [replay_pos] before touching the stream: the bytes
   * sniffed to pick a decoder are still the start of the file to libvips. */
  bool replaying;
  size_t replay_pos;
};

struct RowDecoder
{
  RowStream in;

  /* A WebP decodes through libwebp's incremental decoder, which libvips does not use: its loader
   * takes the whole file before decoding a row. */
  WebPIDecoder* webp;
  bool webp_done;

  /* The WebP's ICC profile, applied to each strip as it lands exactly as the whole decode applies
   * it to the whole image: it is a per-pixel transform. */
  void* icc;
  size_t icc_size;

  VipsSourceCustom* source;
  VipsImage* image;
  VipsRegion* region;
  int width;
  int height;
  int rows_done;
  uint8_t* out;
  jobject buffer;
};

static void
row_stream_release(JNIEnv* env, RowStream* s)
{
  if (s->stream)
    env->DeleteGlobalRef(s->stream);
  if (s->chunk)
    env->DeleteGlobalRef(s->chunk);
  s->stream = nullptr;
  s->chunk = nullptr;
  g_free(s->data);
  s->data = nullptr;
  s->len = s->cap = 0;
}

static void
row_decoder_free(JNIEnv* env, RowDecoder* d)
{
  if (!d)
    return;
  if (d->webp)
    WebPIDelete(d->webp);
  g_free(d->icc);
  if (d->region)
    g_object_unref(d->region);
  if (d->image)
    g_object_unref(d->image);
  if (d->source)
    g_object_unref(d->source);
  if (d->buffer)
    env->DeleteGlobalRef(d->buffer);
  row_stream_release(env, &d->in);
  g_free(d);
}

static bool
tee_append(RowStream* s, const void* bytes, size_t n)
{
  if (s->len + n > s->cap) {
    size_t want = s->cap ? s->cap * 2 : (size_t)ROW_CHUNK * 4;
    while (want < s->len + n)
      want *= 2;
    uint8_t* grown = (uint8_t*)g_try_realloc(s->data, want);
    if (!grown)
      return false;
    s->data = grown;
    s->cap = want;
  }
  memcpy(s->data + s->len, bytes, n);
  s->len += n;
  return true;
}

/* -1 is an error to libvips, 0 the end of the stream. */
static gint64
row_stream_read(VipsSourceCustom*, void* buf, gint64 length, void* user)
{
  RowStream* s = (RowStream*)user;
  if (s->replaying && s->replay_pos < s->len && length > 0) {
    size_t n = VIPS_MIN((size_t)length, s->len - s->replay_pos);
    memcpy(buf, s->data + s->replay_pos, n);
    s->replay_pos += n;
    return (gint64)n;
  }

  JNIEnv* env = s->env;
  if (!env || s->failed || length <= 0)
    return -1;

  jint want = (jint)VIPS_MIN(length, (gint64)ROW_CHUNK);
  jint n = env->CallIntMethod(s->stream, s->read, s->chunk, 0, want);
  if (env->ExceptionCheck()) {
    env->ExceptionClear();
    s->failed = true;
    return -1;
  }
  if (n <= 0)
    return 0;
  /* A stream lying about how much it wrote would otherwise drive an overread. */
  if (n > want) {
    s->failed = true;
    return -1;
  }

  s->total += (guint64)n;
  if (s->total > (guint64)MAX_INPUT_BYTES) {
    s->failed = true;
    return -1;
  }

  env->GetByteArrayRegion(s->chunk, 0, n, (jbyte*)buf);
  if (s->tee && !tee_append(s, buf, (size_t)n)) {
    s->failed = true;
    return -1;
  }
  /* Fresh bytes have been handed out already; replaying must not serve them again. */
  if (s->replaying)
    s->replay_pos = s->len;
  return n;
}

/* Reads what is left of the stream into the tee. */
static void
row_stream_drain(RowStream* s)
{
  /* Whatever a loader already took is in the tee; only the stream's remainder is missing. */
  s->replaying = false;
  std::vector<uint8_t> buf(ROW_CHUNK);
  while (true) {
    gint64 n = row_stream_read(nullptr, buf.data(), ROW_CHUNK, s);
    if (n == 0)
      return;
    if (n < 0)
      fail(s->total > (guint64)MAX_INPUT_BYTES ? EXC_OOM : EXC_DECODE,
           s->total > (guint64)MAX_INPUT_BYTES ? "Out of memory: image exceeds the maximum input size"
                                              : "InputStream.read failed");
  }
}

/* Appends one more read to the tee. False at the end of the stream. */
static bool
row_stream_more(RowStream* s)
{
  const bool replaying = s->replaying;
  s->replaying = false;
  uint8_t buf[16 * 1024];
  gint64 n = row_stream_read(nullptr, buf, sizeof(buf), s);
  s->replaying = replaying;
  if (n < 0)
    fail(EXC_DECODE, "InputStream.read failed");
  return n > 0;
}

static bool
is_webp(const RowStream& in)
{
  return in.len >= 12 && memcmp(in.data, "RIFF", 4) == 0 && memcmp(in.data + 8, "WEBP", 4) == 0;
}

/* Whether [image] comes out of the plain 8-bit path unchanged in a top-to-bottom pass: no second
 * frame, gainmap, rotation or HDR signal, from a loader that decodes row by row. */
static bool
rows_possible(vips::VImage& image, const RowStream& in)
{
  const char* loader = image.get_typeof("vips-loader") != 0 ? image.get_string("vips-loader") : "";
  if (!loader || (strncmp(loader, "jpegload", 8) != 0 && strncmp(loader, "pngload", 7) != 0))
    return false;
  if (image.get_typeof(VIPS_META_N_PAGES) != 0 && image.get_int(VIPS_META_N_PAGES) > 1)
    return false;
  if (has_gainmap(image))
    return false;
  if (image.get_typeof(VIPS_META_ORIENTATION) != 0 && image.get_int(VIPS_META_ORIENTATION) > 1)
    return false;
  if (image.format() != VIPS_FORMAT_UCHAR)
    return false;
  if (image.bands() < 1 || image.bands() > 4)
    return false;

  /* A PNG's cICP chunk sits before its pixels, so the bytes read for the header carry it. */
  ColourSignal signal;
  float peak = 0.0f;
  if (in.data && hdr_find_colour_signal(in.data, in.len, &signal, &peak) &&
      hdr_kind_for_transfer(signal.transfer) != HDR_NONE)
    return false;

  return true;
}

/* Reads the rest of the stream after the tee and hands everything to a whole-file ImageDecoder,
 * freeing [d]. Leaves an exception pending on failure. */
static jobject
whole_from_tee(JNIEnv* env, RowDecoder* d)
{
  row_stream_drain(&d->in);

  Decoder* whole = decoder_new();
  if (!whole)
    fail(EXC_OOM, "Out of memory creating the decoder");
  whole->buffer = d->in.data;
  whole->buffer_size = d->in.len;
  d->in.data = nullptr;
  row_decoder_free(env, d);
  return decoder_object(env, whole);
}

/* The RGBA8 output for [d]'s rows. */
static void
row_alloc_output(JNIEnv* env, RowDecoder* d)
{
  check_dimensions(d->width, d->height);

  const size_t size = checked_buffer_size((guint64)d->width * (guint64)d->height, 4);
  void* data = nullptr;
  jobject buffer = allocate_direct(env, size, &data);
  LocalRef buffer_ref(env, buffer);
  d->out = (uint8_t*)data;
  d->buffer = env->NewGlobalRef(buffer);
  if (!d->buffer)
    fail(EXC_OOM, "Out of memory holding the pixel buffer");
}

/* Wraps [d] in a RowDecoder, which then owns it. The last step of an open: nothing may fail
 * after it, or [d] would be freed under the object's feet. */
static jobject
row_decoder_object(JNIEnv* env, RowDecoder* d, const char* loader)
{
  jstring jloader = env->NewStringUTF(loader);
  if (!jloader || env->ExceptionCheck()) {
    if (env->ExceptionCheck())
      env->ExceptionClear();
    fail(EXC_OOM, "Out of memory creating the loader name");
  }
  LocalRef loader_ref(env, jloader);

  jclass cls = find_class_checked(env, "ca/mpreg/imagedecoder/RowDecoder");
  LocalRef cls_ref(env, cls);
  jmethodID ctor =
    get_method_checked(env, cls, "<init>", "(JIILjava/nio/ByteBuffer;Ljava/lang/String;)V");

  jobject result =
    env->NewObject(cls, ctor, reinterpret_cast<jlong>(d), d->width, d->height, d->buffer, jloader);
  if (!result || env->ExceptionCheck()) {
    if (env->ExceptionCheck())
      env->ExceptionClear();
    if (result)
      env->DeleteLocalRef(result);
    fail(EXC_OOM, "Out of memory creating the decoder object");
  }
  return result;
}

/* VP8X feature flags. EXIF may carry an orientation libvips would apply, which rows from the
 * top cannot; an ICC profile is applied per strip (see webp_colour_rows). */
static const uint8_t WEBP_FLAG_ICC = 0x20;
static const uint8_t WEBP_FLAG_EXIF = 0x08;

/* Copies the ICCP chunk out of the header, reading on until all of it is in. The chunks between
 * VP8X and the bitstream are small, and ICCP comes first of them. */
static void
webp_read_icc(RowDecoder* d)
{
  size_t at = 12;
  while (true) {
    while (d->in.len < at + 8) {
      if (!row_stream_more(&d->in))
        fail(EXC_DECODE, "Truncated WebP header");
    }
    const uint8_t* chunk = d->in.data + at;
    const uint32_t size = chunk[4] | (chunk[5] << 8) | (chunk[6] << 16) | ((uint32_t)chunk[7] << 24);
    if (memcmp(chunk, "VP8 ", 4) == 0 || memcmp(chunk, "VP8L", 4) == 0 ||
        memcmp(chunk, "ANMF", 4) == 0 || memcmp(chunk, "ALPH", 4) == 0)
      return;
    if (size > (uint32_t)MAX_INPUT_BYTES)
      fail(EXC_DECODE, "Invalid WebP chunk size");
    if (memcmp(chunk, "ICCP", 4) == 0) {
      while (d->in.len < at + 8 + size) {
        if (!row_stream_more(&d->in))
          fail(EXC_DECODE, "Truncated WebP ICC profile");
      }
      d->icc = g_try_malloc(size);
      if (!d->icc)
        fail(EXC_OOM, "Out of memory holding the ICC profile");
      memcpy(d->icc, d->in.data + at + 8, size);
      d->icc_size = size;
      return;
    }
    at += 8 + size + (size & 1);
  }
}

/* Runs rows [y0, y1) of the output through the same ICC transform the whole decode uses. */
static void
webp_colour_rows(RowDecoder* d, int y0, int y1)
{
  if (!d->icc || y1 <= y0)
    return;

  const size_t row_bytes = (size_t)d->width * 4;
  uint8_t* rows = d->out + (size_t)y0 * row_bytes;
  const size_t size = (size_t)(y1 - y0) * row_bytes;

  vips::VImage strip =
    vips::VImage::new_from_memory(rows, size, d->width, y1 - y0, 4, VIPS_FORMAT_UCHAR)
      .copy(vips::VImage::option()->set("interpretation", VIPS_INTERPRETATION_sRGB));
  strip.set(VIPS_META_ICC_NAME, (VipsCallbackFn) nullptr, d->icc, d->icc_size);

  vips::VImage out = to_srgb_primaries(strip);
  if (out.bands() != 4 || out.format() != VIPS_FORMAT_UCHAR)
    return;

  /* Not in place: the transform reads the strip while writing its result. */
  std::vector<uint8_t> result(size);
  out.write(vips::VImage::new_from_memory(result.data(), size, d->width, y1 - y0, 4,
                                          VIPS_FORMAT_UCHAR));
  memcpy(rows, result.data(), size);
}

/* A WebP from the header on, or null when it has to decode whole. */
static bool
open_webp_rows(RowDecoder* d)
{
  WebPBitstreamFeatures features;
  VP8StatusCode status;
  while ((status = WebPGetFeatures(d->in.data, d->in.len, &features)) ==
         VP8_STATUS_NOT_ENOUGH_DATA) {
    if (!row_stream_more(&d->in))
      fail(EXC_DECODE, "Truncated WebP header");
  }
  if (status != VP8_STATUS_OK)
    fail(EXC_DECODE, "Invalid WebP header");

  const bool vp8x = d->in.len >= 21 && memcmp(d->in.data + 12, "VP8X", 4) == 0;
  const uint8_t flags = vp8x ? d->in.data[20] : 0;
  if (features.has_animation || (flags & WEBP_FLAG_EXIF))
    return false;
  if (flags & WEBP_FLAG_ICC)
    webp_read_icc(d);

  d->width = features.width;
  d->height = features.height;
  return true;
}

extern "C" JNIEXPORT jobject JNICALL
Java_ca_mpreg_imagedecoder_ImageDecoder_nativeOpenRows(JNIEnv* env, jclass, jobject jstream)
{
  if (!jstream) {
    throw_decode_error(env, EXC_DECODE, "Input stream is null");
    return nullptr;
  }

  RowDecoder* d = g_try_new0(RowDecoder, 1);
  if (!d) {
    throw_decode_error(env, EXC_OOM, "Out of memory creating the decoder");
    return nullptr;
  }
  d->in.env = env;
  d->in.tee = true;

  try {
    jclass stream_cls = env->GetObjectClass(jstream);
    LocalRef stream_cls_ref(env, stream_cls);
    d->in.read = get_method_checked(env, stream_cls, "read", "([BII)I");
    d->in.stream = env->NewGlobalRef(jstream);
    jbyteArray chunk = env->NewByteArray(ROW_CHUNK);
    if (!chunk || env->ExceptionCheck()) {
      if (env->ExceptionCheck())
        env->ExceptionClear();
      fail(EXC_OOM, "Out of memory allocating the read buffer");
    }
    d->in.chunk = (jbyteArray)env->NewGlobalRef(chunk);
    env->DeleteLocalRef(chunk);
    if (!d->in.stream || !d->in.chunk)
      fail(EXC_OOM, "Out of memory holding the stream");

    /* The signature picks the decoder; the bytes stay in the tee for whichever reads the file. */
    while (d->in.len < 16 && row_stream_more(&d->in)) {
    }

    if (is_webp(d->in)) {
      if (!open_webp_rows(d))
        return whole_from_tee(env, d);

      row_alloc_output(env, d);
      d->webp = WebPINewRGB(MODE_RGBA, d->out, (size_t)d->width * d->height * 4, d->width * 4);
      if (!d->webp)
        fail(EXC_OOM, "Out of memory creating the WebP decoder");
      /* Copied in: the tee is done with from here. */
      VP8StatusCode status = WebPIAppend(d->webp, d->in.data, d->in.len);
      if (status != VP8_STATUS_OK && status != VP8_STATUS_SUSPENDED)
        fail(EXC_DECODE, "Invalid WebP data");
      d->webp_done = status == VP8_STATUS_OK;
      d->in.tee = false;
      g_free(d->in.data);
      d->in.data = nullptr;
      d->in.len = d->in.cap = 0;

      jobject result = row_decoder_object(env, d, "webpload_source");
      d->in.env = nullptr;
      return result;
    }

    /* No seek handler: libvips treats the source as a pipe and buffers only what sniffing needs. */
    d->in.replaying = true;
    d->source = vips_source_custom_new();
    if (!d->source)
      throw vips::VError();
    g_signal_connect(d->source, "read", G_CALLBACK(row_stream_read), &d->in);

    VipsImage* raw = vips_image_new_from_source(VIPS_SOURCE(d->source), "", "access",
                                                VIPS_ACCESS_SEQUENTIAL, nullptr);
    if (!raw)
      throw vips::VError();
    vips::VImage image(raw, vips::STEAL);

    check_dimensions(image.width(), image.height());

    if (!rows_possible(image, d->in)) {
      image = vips::VImage();
      return whole_from_tee(env, d);
    }

    /* Rows from here on are decoded straight through; nothing needs the bytes again. */
    d->in.tee = false;

    vips::VImage frame = to_srgb_primaries(image);
    if (frame.interpretation() != VIPS_INTERPRETATION_sRGB)
      frame = frame.colourspace(VIPS_INTERPRETATION_sRGB);
    if (frame.bands() < 4)
      frame = frame.bandjoin(255);
    if (frame.bands() > 4)
      frame = frame.extract_band(0, vips::VImage::option()->set("n", 4));
    if (frame.format() != VIPS_FORMAT_UCHAR)
      frame = frame.cast(VIPS_FORMAT_UCHAR);

    d->width = frame.width();
    d->height = frame.height();
    d->image = frame.get_image();
    g_object_ref(d->image);
    d->region = vips_region_new(d->image);
    if (!d->region)
      throw vips::VError();

    row_alloc_output(env, d);
    const char* loader = image.get_string("vips-loader");
    jobject result = row_decoder_object(env, d, loader ? loader : "");
    d->in.env = nullptr;
    return result;
  } catch (const DecodeError& e) {
    row_decoder_free(env, d);
    throw_decode_error(env, e.cls, e.msg.c_str());
    return nullptr;
  } catch (const vips::VError& e) {
    const bool stream_failed = d && d->in.failed;
    row_decoder_free(env, d);
    if (stream_failed) {
      vips_error_clear();
      throw_decode_error(env, EXC_DECODE, "InputStream.read failed");
    } else {
      throw_vips_error(env, e);
    }
    return nullptr;
  } catch (const std::bad_alloc&) {
    row_decoder_free(env, d);
    vips_error_clear();
    throw_decode_error(env, EXC_OOM, "Out of memory reading the image header");
    return nullptr;
  } catch (...) {
    row_decoder_free(env, d);
    vips_error_clear();
    throw_decode_error(env, EXC_DECODE, "Unknown error reading the image header");
    return nullptr;
  }
}

/* Decodes up to [max_rows] more rows into the buffer, blocking on the stream for their bytes.
 * Returns the rows decoded in total. */
extern "C" JNIEXPORT jint JNICALL
Java_ca_mpreg_imagedecoder_RowDecoder_nativeDecodeRows(JNIEnv* env, jobject obj, jint max_rows)
{
  RowDecoder* d = reinterpret_cast<RowDecoder*>(get_ptr(env, obj));
  if (!d) {
    throw_decode_error(env, EXC_DECODE, "RowDecoder has been closed");
    return 0;
  }
  if (d->rows_done >= d->height || max_rows <= 0)
    return d->rows_done;

  d->in.env = env;
  try {
    if (d->webp) {
      const int target = VIPS_MIN(d->height, d->rows_done + max_rows);
      int last_y = 0;
      std::vector<uint8_t> buf;
      while (true) {
        if (!WebPIDecGetRGB(d->webp, &last_y, nullptr, nullptr, nullptr))
          last_y = 0;
        if (last_y >= target || d->webp_done)
          break;
        if (buf.empty())
          buf.resize(ROW_CHUNK);
        gint64 n = row_stream_read(nullptr, buf.data(), ROW_CHUNK, &d->in);
        if (n < 0)
          fail(EXC_DECODE, "InputStream.read failed");
        if (n == 0)
          fail(EXC_DECODE, "Truncated WebP");
        VP8StatusCode status = WebPIAppend(d->webp, buf.data(), (size_t)n);
        if (status == VP8_STATUS_OK)
          d->webp_done = true;
        else if (status != VP8_STATUS_SUSPENDED)
          fail(EXC_DECODE, "Invalid WebP data");
      }
      if (d->webp_done && WebPIDecGetRGB(d->webp, &last_y, nullptr, nullptr, nullptr))
        last_y = d->height;
      const int done = VIPS_MIN(VIPS_MAX(last_y, d->rows_done), d->height);
      webp_colour_rows(d, d->rows_done, done);
      d->rows_done = done;
    } else {
    const int y = d->rows_done;
    const int n = VIPS_MIN(max_rows, d->height - y);
    VipsRect rect = { 0, y, d->width, n };
    if (vips_region_prepare(d->region, &rect))
      throw vips::VError();

    const size_t row_bytes = (size_t)d->width * 4;
    for (int i = 0; i < n; i++)
      memcpy(d->out + (size_t)(y + i) * row_bytes, VIPS_REGION_ADDR(d->region, 0, y + i), row_bytes);
    d->rows_done = y + n;
    }
  } catch (const DecodeError& e) {
    d->in.env = nullptr;
    throw_decode_error(env, e.cls, e.msg.c_str());
    return d->rows_done;
  } catch (const vips::VError& e) {
    d->in.env = nullptr;
    if (d->in.failed) {
      vips_error_clear();
      throw_decode_error(env, EXC_DECODE, "InputStream.read failed");
    } else {
      throw_vips_error(env, e);
    }
    return d->rows_done;
  } catch (...) {
    d->in.env = nullptr;
    vips_error_clear();
    throw_decode_error(env, EXC_DECODE, "Unknown error decoding rows");
    return d->rows_done;
  }
  d->in.env = nullptr;

  /* Done: the pipeline and the stream are dead weight until close. */
  if (d->rows_done >= d->height) {
    if (d->webp)
      WebPIDelete(d->webp);
    d->webp = nullptr;
    if (d->region)
      g_object_unref(d->region);
    d->region = nullptr;
    if (d->image)
      g_object_unref(d->image);
    d->image = nullptr;
    if (d->source)
      g_object_unref(d->source);
    d->source = nullptr;
    row_stream_release(env, &d->in);
  }
  return d->rows_done;
}

extern "C" JNIEXPORT void JNICALL
Java_ca_mpreg_imagedecoder_RowDecoder_nativeFree(JNIEnv* env, jobject obj)
{
  row_decoder_free(env, reinterpret_cast<RowDecoder*>(take_ptr(env, obj)));
}

/* ---------------------------------------------------------- frame playback
 *
 * An animation's frames in order, each decoded once: libvips loads every page as one tall image
 * (n = -1) with sequential access, and frame i is its rows [i * page height, (i + 1) * page
 * height). decode(page) cannot do that - each call composes the animation from its first frame
 * again, so frame i costs i frames. Wrapping past the last frame reopens the file. Reads the
 * ImageDecoder's buffer, so it must be closed first. */

struct Frames
{
  const uint8_t* file;
  size_t file_size;
  VipsImage* image;
  VipsRegion* region;
  int width;
  int page_height;
  int pages;
  int next;
  uint8_t* out;
  jobject buffer;
};

static void
frames_release_pipeline(Frames* f)
{
  if (f->region)
    g_object_unref(f->region);
  if (f->image)
    g_object_unref(f->image);
  f->region = nullptr;
  f->image = nullptr;
}

static void
frames_free(JNIEnv* env, Frames* f)
{
  if (!f)
    return;
  frames_release_pipeline(f);
  if (f->buffer)
    env->DeleteGlobalRef(f->buffer);
  g_free(f);
}

/* The same 8-bit pipeline nativeDecode runs, over every frame at once. */
static void
frames_open_pipeline(Frames* f)
{
  frames_release_pipeline(f);

  vips::VImage all = vips::VImage::new_from_buffer(
    f->file, f->file_size, "",
    vips::VImage::option()->set("access", VIPS_ACCESS_SEQUENTIAL)->set("n", -1));

  vips::VImage frame = to_srgb_primaries(all);
  if (frame.interpretation() != VIPS_INTERPRETATION_sRGB)
    frame = frame.colourspace(VIPS_INTERPRETATION_sRGB);
  if (frame.bands() < 4)
    frame = frame.bandjoin(255);
  if (frame.bands() > 4)
    frame = frame.extract_band(0, vips::VImage::option()->set("n", 4));
  if (frame.format() != VIPS_FORMAT_UCHAR)
    frame = frame.cast(VIPS_FORMAT_UCHAR);

  if (frame.width() != f->width || frame.height() != f->page_height * f->pages)
    fail(EXC_DECODE, "Animation frames changed size");

  f->image = frame.get_image();
  g_object_ref(f->image);
  f->region = vips_region_new(f->image);
  if (!f->region)
    throw vips::VError();
  f->next = 0;
}

extern "C" JNIEXPORT jobject JNICALL
Java_ca_mpreg_imagedecoder_ImageDecoder_nativeFrames(JNIEnv* env, jobject obj)
{
  Frames* f = nullptr;
  try {
    Decoder* decoder = decoder_for(env, obj);
    /* Only what the plain 8-bit path hands back unchanged: HDR frames and a rotation go
     * through steps a stacked image cannot take frame by frame. */
    if (decoder->pages < 2 || decoder->hdr_kind != HDR_NONE)
      return nullptr;

    vips::VImage header = vips::VImage::new_from_buffer(
      decoder->buffer, decoder->buffer_size, "",
      vips::VImage::option()->set("access", VIPS_ACCESS_SEQUENTIAL)->set("n", -1));
    if (header.get_typeof(VIPS_META_ORIENTATION) != 0 && header.get_int(VIPS_META_ORIENTATION) > 1)
      return nullptr;
    const int page_height = vips_image_get_page_height(header.get_image());
    if (page_height <= 0 || header.height() % page_height != 0)
      return nullptr;
    const int pages = header.height() / page_height;
    if (pages < 2)
      return nullptr;
    check_dimensions(header.width(), page_height);

    f = g_try_new0(Frames, 1);
    if (!f)
      fail(EXC_OOM, "Out of memory creating the frame decoder");
    f->file = decoder->buffer;
    f->file_size = decoder->buffer_size;
    f->width = header.width();
    f->page_height = page_height;
    f->pages = pages;
    header = vips::VImage();

    frames_open_pipeline(f);

    const size_t size = checked_buffer_size((guint64)f->width * (guint64)f->page_height, 4);
    void* data = nullptr;
    jobject buffer = allocate_direct(env, size, &data);
    LocalRef buffer_ref(env, buffer);
    f->out = (uint8_t*)data;
    f->buffer = env->NewGlobalRef(buffer);
    if (!f->buffer)
      fail(EXC_OOM, "Out of memory holding the frame buffer");

    jclass cls = find_class_checked(env, "ca/mpreg/imagedecoder/FrameDecoder");
    LocalRef cls_ref(env, cls);
    jmethodID ctor = get_method_checked(env, cls, "<init>", "(JIIILjava/nio/ByteBuffer;)V");
    jobject result = env->NewObject(cls, ctor, reinterpret_cast<jlong>(f), f->width, f->page_height,
                                    f->pages, f->buffer);
    if (!result || env->ExceptionCheck()) {
      if (env->ExceptionCheck())
        env->ExceptionClear();
      if (result)
        env->DeleteLocalRef(result);
      fail(EXC_OOM, "Out of memory creating the frame decoder object");
    }
    return result;
  } catch (const DecodeError& e) {
    frames_free(env, f);
    throw_decode_error(env, e.cls, e.msg.c_str());
  } catch (const vips::VError& e) {
    frames_free(env, f);
    throw_vips_error(env, e);
  } catch (...) {
    frames_free(env, f);
    vips_error_clear();
    throw_decode_error(env, EXC_DECODE, "Unknown error opening the frames");
  }
  return nullptr;
}

/* Decodes the next frame into the buffer and returns its index. */
extern "C" JNIEXPORT jint JNICALL
Java_ca_mpreg_imagedecoder_FrameDecoder_nativeNext(JNIEnv* env, jobject obj)
{
  Frames* f = reinterpret_cast<Frames*>(get_ptr(env, obj));
  if (!f) {
    throw_decode_error(env, EXC_DECODE, "FrameDecoder has been closed");
    return -1;
  }
  try {
    if (f->next >= f->pages || !f->region)
      frames_open_pipeline(f);

    const int index = f->next;
    VipsRect rect = { 0, index * f->page_height, f->width, f->page_height };
    if (vips_region_prepare(f->region, &rect))
      throw vips::VError();

    const size_t row_bytes = (size_t)f->width * 4;
    for (int y = 0; y < f->page_height; y++)
      memcpy(f->out + (size_t)y * row_bytes,
             VIPS_REGION_ADDR(f->region, 0, index * f->page_height + y), row_bytes);
    f->next = index + 1;
    return index;
  } catch (const DecodeError& e) {
    frames_release_pipeline(f);
    throw_decode_error(env, e.cls, e.msg.c_str());
  } catch (const vips::VError& e) {
    frames_release_pipeline(f);
    throw_vips_error(env, e);
  } catch (...) {
    frames_release_pipeline(f);
    vips_error_clear();
    throw_decode_error(env, EXC_DECODE, "Unknown error decoding a frame");
  }
  return -1;
}

extern "C" JNIEXPORT void JNICALL
Java_ca_mpreg_imagedecoder_FrameDecoder_nativeFree(JNIEnv* env, jobject obj)
{
  frames_free(env, reinterpret_cast<Frames*>(take_ptr(env, obj)));
}

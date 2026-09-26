package ca.mpreg.imagedecoder

import java.io.Closeable
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * A still image decoded top to bottom while its bytes are still arriving, from
 * [ImageDecoder.open].
 *
 * [image] is allocated whole up front, in [ImageDecoder.PixelFormat.RGBA8] at [width] x [height],
 * and fills from the top: rows below [rowsDecoded] are still zero. [decodeRows] blocks on the
 * stream for exactly as many bytes as its rows need, so a baseline JPEG or a non-interlaced PNG
 * can be shown while it downloads. Formats that decode whole (progressive JPEG, interlaced PNG)
 * still come out this way, just with every row landing in the last call.
 *
 * Holds the stream until the last row; [close] releases it earlier. Closing does not wait for a
 * [decodeRows] blocked in a read, so close the stream first to unblock it.
 */
class RowDecoder private constructor(
    // Read and cleared by native code; see nativeFree.
    private var ptr: Long,
    val width: Int,
    val height: Int,
    val image: ByteBuffer,
    private val loader: String,
) : Closeable {
    private val closed = AtomicBoolean(false)

    /** Rows of [image] decoded so far, from the top. */
    @Volatile
    var rowsDecoded: Int = 0
        private set

    val isComplete: Boolean get() = rowsDecoded >= height

    /** As [ImageDecoder.format]. */
    val format: String
        get() = when {
            loader.startsWith("jpeg") -> "jpeg"
            loader.startsWith("png") -> "png"
            else -> loader.removeSuffix("load_source")
        }

    /**
     * Decodes up to [maxRows] more rows, blocking until their bytes have arrived. Returns
     * [rowsDecoded].
     *
     * @throws ImageDecoder.DecodeException if the stream fails or the data is malformed, or this
     *   decoder is closed.
     */
    @Synchronized
    @Throws(ImageDecoder.DecodeException::class)
    fun decodeRows(maxRows: Int): Int {
        if (closed.get() || ptr == 0L) throw ImageDecoder.DecodeException("RowDecoder has been closed")
        if (isComplete) return rowsDecoded
        rowsDecoded = nativeDecodeRows(maxRows)
        return rowsDecoded
    }

    private external fun nativeDecodeRows(maxRows: Int): Int

    /** Releases the decoder and the stream. Idempotent. [image] stays valid. */
    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        synchronized(this) { nativeFree() }
    }

    @Deprecated("Call close(); the finalizer only catches a caller who forgot.")
    protected fun finalize() {
        close()
    }

    private external fun nativeFree()
}

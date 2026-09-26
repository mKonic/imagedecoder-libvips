package ca.mpreg.imagedecoder

import java.io.Closeable
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean

/**
 * An animation's frames in order, each decoded once, from [ImageDecoder.frames]: for playing an
 * animation without holding every frame, where [ImageDecoder.decode] would compose the animation
 * from its first frame again for each one.
 *
 * [next] writes each frame into [image], one reused [ImageDecoder.PixelFormat.RGBA8] buffer at
 * [width] x [height], so a frame is only valid until the next call. After the last frame it
 * starts over. Reads its [ImageDecoder]'s data, which closes this along with itself.
 */
class FrameDecoder private constructor(
    // Read and cleared by native code; see nativeFree.
    private var ptr: Long,
    val width: Int,
    val height: Int,
    val frameCount: Int,
    val image: ByteBuffer,
) : Closeable {
    private val closed = AtomicBoolean(false)

    /**
     * Decodes the next frame into [image] and returns its index.
     *
     * @throws ImageDecoder.DecodeException if the data is malformed, or this decoder is closed.
     */
    @Synchronized
    @Throws(ImageDecoder.DecodeException::class)
    fun next(): Int {
        if (closed.get() || ptr == 0L) throw ImageDecoder.DecodeException("FrameDecoder has been closed")
        return nativeNext()
    }

    private external fun nativeNext(): Int

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

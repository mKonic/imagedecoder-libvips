package ca.mpreg.imagedecoder

import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.LinearGradient
import android.graphics.Paint
import android.graphics.Shader
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.nio.ByteBuffer

/**
 * A row decode must hand back exactly what the whole-file decode does for the same bytes, however
 * the bytes trickle in, and must never report a row before its bytes have arrived.
 */
@RunWith(AndroidJUnit4::class)
class RowDecoderTest {

    /** Gradients and shapes, so a row shifted or a channel swapped cannot compare equal. */
    private fun picture(width: Int, height: Int, alpha: Boolean): Bitmap {
        val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
        val canvas = Canvas(bitmap)
        if (alpha) canvas.drawColor(Color.TRANSPARENT) else canvas.drawColor(Color.WHITE)
        val paint = Paint(Paint.ANTI_ALIAS_FLAG)
        paint.shader = LinearGradient(
            0f, 0f, width.toFloat(), height.toFloat(),
            intArrayOf(Color.RED, Color.GREEN, Color.BLUE, if (alpha) 0x80FFFF00.toInt() else Color.BLACK),
            null,
            Shader.TileMode.CLAMP,
        )
        canvas.drawRect(0f, 0f, width.toFloat(), height * 0.8f, paint)
        paint.shader = null
        paint.color = if (alpha) 0x40000000 else Color.MAGENTA
        for (i in 0 until 12) canvas.drawCircle(width * (i % 4 + 0.5f) / 4, height * (i / 4 + 0.5f) / 3, width / 10f, paint)
        return bitmap
    }

    private fun encode(bitmap: Bitmap, format: Bitmap.CompressFormat, quality: Int = 90): ByteArray =
        ByteArrayOutputStream().also { bitmap.compress(format, quality, it) }.toByteArray()

    /** Hands out at most [chunk] bytes a read, and counts how far the reader has got. */
    private class Trickle(private val bytes: ByteArray, private val chunk: Int) : InputStream() {
        var position = 0
            private set

        override fun read(): Int = if (position < bytes.size) bytes[position++].toInt() and 0xFF else -1

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (position >= bytes.size) return -1
            val n = minOf(len, chunk, bytes.size - position)
            System.arraycopy(bytes, position, b, off, n)
            position += n
            return n
        }
    }

    private fun ByteBuffer.toArray(): ByteArray {
        val copy = duplicate()
        copy.rewind()
        return ByteArray(copy.remaining()).also { copy.get(it) }
    }

    private fun whole(bytes: ByteArray): ByteArray =
        ImageDecoder.new(bytes.inputStream()).use { it.decode().image.toArray() }

    /** Row decodes [bytes] in [chunk]-byte reads, [rows] rows a call, and returns the pixels. */
    private fun rows(bytes: ByteArray, chunk: Int, rows: Int): Pair<ByteArray, Int> {
        val input = Trickle(bytes, chunk)
        val opened = ImageDecoder.open(input)
        assertTrue(
            "expected a row decoder, got $opened for " +
                bytes.copyOf(48).joinToString(" ") { "%02x".format(it) },
            opened is ImageDecoder.Opened.Rows,
        )
        val decoder = (opened as ImageDecoder.Opened.Rows).decoder
        var calls = 0
        decoder.use {
            while (!it.isComplete) {
                val before = it.rowsDecoded
                val after = it.decodeRows(rows)
                assertTrue("no progress at row $before", after > before)
                calls++
            }
            return it.image.toArray() to calls
        }
    }

    private fun check(bytes: ByteArray, name: String) {
        val expected = whole(bytes)
        for ((chunk, rows) in listOf(bytes.size to 10_000, 4096 to 64, 97 to 7)) {
            val (actual, _) = rows(bytes, chunk, rows)
            assertArrayEquals("$name, $chunk-byte reads", expected, actual)
        }
    }

    @Test
    fun jpegMatchesTheWholeDecode() = check(encode(picture(640, 1500, false), Bitmap.CompressFormat.JPEG), "jpeg")

    @Test
    fun pngMatchesTheWholeDecode() = check(encode(picture(333, 700, true), Bitmap.CompressFormat.PNG), "png")

    @Test
    fun lossyWebpMatchesTheWholeDecode() =
        check(encode(picture(640, 1500, false), Bitmap.CompressFormat.WEBP_LOSSY), "lossy webp")

    @Test
    fun lossyWebpWithAlphaMatchesTheWholeDecode() =
        check(encode(picture(320, 480, true), Bitmap.CompressFormat.WEBP_LOSSY), "lossy webp with alpha")

    @Test
    fun losslessWebpMatchesTheWholeDecode() =
        check(encode(picture(320, 900, true), Bitmap.CompressFormat.WEBP_LOSSLESS), "lossless webp")

    /** The point of the whole thing: the top of the picture before the file has finished arriving. */
    @Test
    fun firstRowsComeBeforeTheLastByte() {
        for ((format, name) in listOf(
            Bitmap.CompressFormat.JPEG to "jpeg",
            Bitmap.CompressFormat.WEBP_LOSSY to "webp",
        )) {
            val bytes = encode(picture(640, 3000, false), format)
            val input = Trickle(bytes, 1024)
            val decoder = (ImageDecoder.open(input) as ImageDecoder.Opened.Rows).decoder
            decoder.use {
                val rows = it.decodeRows(64)
                assertTrue("$name: $rows rows", rows in 1 until it.height)
                assertTrue("$name: read ${input.position} of ${bytes.size}", input.position < bytes.size / 2)
            }
        }
    }

    @Test
    fun aSixteenBitPngOpensWhole() {
        // A 16-bit PNG cannot come out of the 8-bit row path unchanged.
        val bitmap = picture(64, 64, false).copy(Bitmap.Config.RGBA_F16, false)
        val bytes = encode(bitmap, Bitmap.CompressFormat.PNG)
        ImageDecoder.open(bytes.inputStream()).use {
            assertTrue("expected a whole decoder, got $it", it is ImageDecoder.Opened.Whole)
            assertEquals(64, (it as ImageDecoder.Opened.Whole).decoder.decode().width)
        }
    }

    @Test
    fun aTruncatedFileFailsInsteadOfHanging() {
        val bytes = encode(picture(640, 1500, false), Bitmap.CompressFormat.WEBP_LOSSY)
        val cut = bytes.copyOf(bytes.size / 3)
        val decoder = (ImageDecoder.open(cut.inputStream()) as ImageDecoder.Opened.Rows).decoder
        decoder.use {
            try {
                while (!it.isComplete) it.decodeRows(64)
                throw AssertionError("decoded a third of a file to the end")
            } catch (_: ImageDecoder.DecodeException) {
            }
        }
    }
}

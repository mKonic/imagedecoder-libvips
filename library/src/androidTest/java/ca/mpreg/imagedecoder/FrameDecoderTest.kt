package ca.mpreg.imagedecoder

import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test
import org.junit.runner.RunWith
import java.nio.ByteBuffer

/** Frames played in order must be the frames decode(page) gives, and must keep looping. */
@RunWith(AndroidJUnit4::class)
class FrameDecoderTest {

    private fun asset(name: String): ByteArray =
        InstrumentationRegistry.getInstrumentation().context.assets.open(name).use { it.readBytes() }

    private fun ByteBuffer.toArray(): ByteArray {
        val copy = duplicate()
        copy.rewind()
        return ByteArray(copy.remaining()).also { copy.get(it) }
    }

    private fun check(name: String) {
        ImageDecoder.new(asset(name).inputStream()).use { decoder ->
            val expected = (0 until decoder.pages).map { decoder.decode(it).image.toArray() }
            val frames = decoder.frames()
            assertNotNull("$name has no frame decoder", frames)
            frames!!
            assertEquals(decoder.pages, frames.frameCount)
            // Twice round, so the wrap back to the first frame is covered.
            for (round in 0 until 2) {
                for (i in 0 until frames.frameCount) {
                    assertEquals(i, frames.next())
                    assertArrayEquals("$name frame $i, round $round", expected[i], frames.image.toArray())
                }
            }
        }
    }

    @Test
    fun webpFramesMatchDecode() = check("anim.webp")

    @Test
    fun gifFramesMatchDecode() = check("anim.gif")

    @Test
    fun aStillImageHasNoFrames() {
        val png = ImageDecoder.new(asset("anim.webp").inputStream()).use { it.encode(".png", 0).use { r -> r.bytes.toArray() } }
        ImageDecoder.new(png.inputStream()).use { assertNull(it.frames()) }
    }

    @Test
    fun closingTheDecoderClosesItsFrames() {
        val decoder = ImageDecoder.new(asset("anim.gif").inputStream())
        val frames = decoder.frames()!!
        frames.next()
        decoder.close()
        assertThrows(ImageDecoder.DecodeException::class.java) { frames.next() }
    }
}

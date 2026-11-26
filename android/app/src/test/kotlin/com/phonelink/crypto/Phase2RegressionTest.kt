package com.phonelink.crypto

import com.phonelink.files.FileOperationHandler
import com.phonelink.files.StorageAccessLayer
import org.json.JSONObject
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.io.File
import java.nio.file.Files
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Phase2RegressionTest {

    private lateinit var tempRoot: File
    private lateinit var storage: StorageAccessLayer
    private lateinit var handler: FileOperationHandler

    @Before
    fun setUp() {
        tempRoot = Files.createTempDirectory("phonelink_phase2_test").toFile()
        storage = StorageAccessLayer(tempRoot) { true }
        handler = FileOperationHandler(storage)
    }

    @After
    fun tearDown() {
        tempRoot.deleteRecursively()
    }

    @Test
    fun testRfc7748X25519TestVectorAndJcaInterop() {
        // RFC 7748 Section 6.1 vector
        val alicePriv = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        val alicePubExpected = hexToBytes("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val bobPriv = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
        val bobPubExpected = hexToBytes("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        val sharedExpected = hexToBytes("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")

        assertTrue(alicePubExpected.contentEquals(Curve25519Primitives.x25519PublicFromPrivate(alicePriv)))
        assertTrue(bobPubExpected.contentEquals(Curve25519Primitives.x25519PublicFromPrivate(bobPriv)))
        assertTrue(sharedExpected.contentEquals(Curve25519Primitives.x25519ComputeSharedSecret(alicePriv, bobPubExpected)))
        assertTrue(sharedExpected.contentEquals(Curve25519Primitives.x25519ComputeSharedSecret(bobPriv, alicePubExpected)))
    }

    @Test
    fun testRfc8032Ed25519VerificationVector() {
        // RFC 8032 Section 7.1 TV1 (empty message)
        val pk = hexToBytes("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        val sig = hexToBytes(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155" +
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        assertTrue(Curve25519Primitives.ed25519Verify(sig, ByteArray(0), pk))
        assertFalse(Curve25519Primitives.ed25519Verify(sig, byteArrayOf(0x01), pk))
    }

    @Test
    fun testAuthenticatedE2ESessionRejectsSpoofedInitAndReplayedSeq() {
        // Use real JDK Ed25519 keypair to simulate Mac identity
        val kpg = java.security.KeyPairGenerator.getInstance("Ed25519")
        val macIdentity = kpg.generateKeyPair()
        val macPubRaw = macIdentity.public.encoded.let { it.copyOfRange(it.size - 32, it.size) }

        val signer = com.phonelink.crypto.SoftwareEcKeySigner()
        val sent = mutableListOf<ByteArray>()
        val session = E2EPeerSession(
            sendFunction = { sent.add(it); true },
            messageDispatcher = { plain, _ -> plain },
            signer = signer,
            peerPublicKeyProvider = { macPubRaw },
            requirePeerAuth = true
        )

        val macEph = E2EEncryptionManager()
        val ts = System.currentTimeMillis()
        val badInit = JSONObject().apply {
            put("type", "E2E_INIT")
            put("ephemeral_public_key", Base64.getEncoder().encodeToString(macEph.getRawPublicKey()))
            put("timestamp", ts)
            put("signature", Base64.getEncoder().encodeToString(ByteArray(64))) // invalid sig
        }
        assertFalse(session.handleIncomingMessage(badInit.toString().toByteArray()))
        assertTrue(sent.isEmpty())

        // Valid signed E2E_INIT
        val transcript = E2EEncryptionManager.buildHandshakeTranscript(macEph.getRawPublicKey(), ts)
        val edSig = java.security.Signature.getInstance("Ed25519").run {
            initSign(macIdentity.private)
            update(transcript)
            sign()
        }
        val goodInit = JSONObject().apply {
            put("type", "E2E_INIT")
            put("ephemeral_public_key", Base64.getEncoder().encodeToString(macEph.getRawPublicKey()))
            put("timestamp", ts)
            put("signature", Base64.getEncoder().encodeToString(edSig))
        }
        assertTrue(session.handleIncomingMessage(goodInit.toString().toByteArray()))
        assertEquals(1, sent.size)

        val ackJson = JSONObject(String(sent[0]))
        val ackPub = Base64.getDecoder().decode(ackJson.getString("ephemeral_public_key"))
        val ackTs = ackJson.getLong("timestamp")
        val ackSig = Base64.getDecoder().decode(ackJson.getString("signature"))
        assertTrue(
            com.phonelink.crypto.KeyManager.verifyExternal(
                java.security.KeyFactory.getInstance("EC")
                    .generatePublic(java.security.spec.X509EncodedKeySpec(signer.publicKeyEncoded)),
                E2EEncryptionManager.buildHandshakeTranscript(ackPub, ackTs),
                ackSig
            )
        )

        val macKeys = macEph.deriveSessionKeys(E2EEncryptionManager.parsePublicKey(ackPub))
        val seq1Payload = E2EEncryptionManager.encryptAESGCM(
            macKeys.keyMacToAndroid,
            """{"ping":1}""".toByteArray(),
            E2EEncryptionManager.buildPayloadAad("M2A", 1L)
        )
        val wrapped1 = JSONObject().apply {
            put("type", "E2E_PAYLOAD")
            put("seq", 1L)
            put("ciphertext", Base64.getEncoder().encodeToString(seq1Payload))
        }.toString().toByteArray()

        sent.clear()
        assertTrue(session.handleIncomingMessage(wrapped1))
        assertEquals(1, sent.size)
        // Replaying seq=1 must be rejected
        assertFalse(session.handleIncomingMessage(wrapped1))
    }

    @Test
    fun testStorageAccessAllowsUserFilesContainingKeyAndBlocksSiblingRoot() {
        val monkey = File(tempRoot, "monkey.jpg").apply { writeText("banana") }
        val res = storage.resolveAndValidatePath("monkey.jpg")
        assertTrue(res.isSuccess)
        assertEquals(monkey.canonicalPath, res.getOrThrow().canonicalPath)

        val sibling = File(tempRoot.parentFile, "${tempRoot.name}_sibling").apply { mkdirs() }
        try {
            val evil = File(sibling, "secret.txt").apply { writeText("nope") }
            val denied = storage.writeChunk(evil, 0L, "x".toByteArray())
            assertTrue(denied.isFailure)
        } finally {
            sibling.deleteRecursively()
        }
    }

    @Test
    fun testDownloadResumeAtExactTotalSizeEmitsFinalEmptyChunk() {
        val data = ByteArray(1024) { (it % 251).toByte() }
        File(tempRoot, "done.bin").writeBytes(data)

        val chunks = mutableListOf<JSONObject>()
        val count = handler.streamFileChunks(
            filePath = "done.bin",
            transferId = "tx-eof",
            startOffset = 1024L,
            chunkSizeBytes = 512
        ) { raw ->
            chunks.add(JSONObject(String(raw)).getJSONObject("file_chunk"))
            true
        }
        assertEquals(1L, count)
        assertTrue(chunks[0].getBoolean("is_final_chunk"))
        assertEquals(1024L, chunks[0].getLong("offset"))
        assertEquals("", chunks[0].getString("data"))
    }

    private fun hexToBytes(hex: String): ByteArray =
        hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

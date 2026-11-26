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
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class E2EPeerSessionTest {

    private lateinit var tempRoot: File
    private lateinit var storageAccessLayer: StorageAccessLayer
    private lateinit var fileHandler: FileOperationHandler

    @Before
    fun setUp() {
        tempRoot = Files.createTempDirectory("phonelink_e2e_peer_session_test").toFile()
        storageAccessLayer = StorageAccessLayer(tempRoot) { true }
        fileHandler = FileOperationHandler(storageAccessLayer)
    }

    @After
    fun tearDown() {
        tempRoot.deleteRecursively()
    }

    @Test
    fun testE2EHandshakeAndEncryptedFileListRequest() {
        // Staged test files
        File(tempRoot, "document.pdf").apply { writeText("PDF File Content") }

        // Fake Mac endpoint
        val macManager = E2EEncryptionManager()
        val macEphemeralPub = macManager.getRawPublicKey()

        val sentFrames = mutableListOf<ByteArray>()
        val androidSession = E2EPeerSession(
            sendFunction = { bytes ->
                sentFrames.add(bytes)
                true
            },
            messageDispatcher = { plaintext -> fileHandler.processApplicationMessage(plaintext) }
        )

        // 1. Mac initiates handshake: sends E2E_INIT
        val initJson = JSONObject().apply {
            put("type", "E2E_INIT")
            put("ephemeral_public_key", Base64.getEncoder().encodeToString(macEphemeralPub))
            put("timestamp", System.currentTimeMillis())
        }
        val handledInit = androidSession.handleIncomingMessage(initJson.toString().toByteArray(Charsets.UTF_8))
        assertTrue(handledInit)
        assertEquals(1, sentFrames.size)

        // Android replied with E2E_ACK
        val ackJson = JSONObject(String(sentFrames[0], Charsets.UTF_8))
        assertEquals("E2E_ACK", ackJson.getString("type"))
        val androidEphemeralPub = Base64.getDecoder().decode(ackJson.getString("ephemeral_public_key"))

        // Mac derives keys
        val androidPubKey = E2EEncryptionManager.parsePublicKey(androidEphemeralPub)
        val macSessionKeys = macManager.deriveSessionKeys(androidPubKey)
        assertNotNull(androidSession.getSessionKeys())

        // 2. Mac sends encrypted FileListRequest
        val requestJson = JSONObject().apply {
            put("schema_version", 1)
            put("message_id", "req-msg-001")
            put("timestamp", System.currentTimeMillis())
            put("file_list_req", JSONObject().apply {
                put("request_id", "req-fl-100")
                put("target_directory", "")
            })
        }
        val encryptedRequest = E2EEncryptionManager.encryptAESGCM(
            macSessionKeys.keyMacToAndroid,
            requestJson.toString().toByteArray(Charsets.UTF_8),
            E2EEncryptionManager.buildPayloadAad("M2A", 1L)
        )

        // Wrap as E2E_PAYLOAD
        val payloadJson = JSONObject().apply {
            put("type", "E2E_PAYLOAD")
            put("seq", 1L)
            put("ciphertext", Base64.getEncoder().encodeToString(encryptedRequest))
        }

        sentFrames.clear()
        val handledPayload = androidSession.handleIncomingMessage(payloadJson.toString().toByteArray(Charsets.UTF_8))
        assertTrue(handledPayload)
        assertEquals(1, sentFrames.size)

        // 3. Android replied with encrypted E2E_PAYLOAD
        val replyJson = JSONObject(String(sentFrames[0], Charsets.UTF_8))
        assertEquals("E2E_PAYLOAD", replyJson.getString("type"))
        val replySeq = replyJson.getLong("seq")
        val responseCiphertext = Base64.getDecoder().decode(replyJson.getString("ciphertext"))

        // Mac decrypts with keyAndroidToMac + AAD
        val decryptedResponseBytes = E2EEncryptionManager.decryptAESGCM(
            macSessionKeys.keyAndroidToMac,
            responseCiphertext,
            E2EEncryptionManager.buildPayloadAad("A2M", replySeq)
        )
        val responseObj = JSONObject(String(decryptedResponseBytes, Charsets.UTF_8))
        assertEquals(1, responseObj.getInt("schema_version"))
        assertTrue(responseObj.has("file_list_resp"))

        val fileListResp = responseObj.getJSONObject("file_list_resp")
        assertEquals("STATUS_OK", fileListResp.getString("status"))
        val items = fileListResp.getJSONArray("items")
        assertEquals(1, items.length())
        assertEquals("document.pdf", items.getJSONObject(0).getString("name"))
    }
}

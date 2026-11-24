package com.phonelink.transport

import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class NetworkTransportTest {

    private lateinit var mockWebServer: MockWebServer
    private lateinit var transport: NetworkTransport

    @Before
    fun setUp() {
        mockWebServer = MockWebServer()
        mockWebServer.start()
        transport = NetworkTransport(
            config = NetworkTransport.TransportConfig(
                maxRetryAttempts = 2,
                retryBackoffBaseMillis = 50
            )
        )
    }

    @After
    fun tearDown() {
        try {
            transport.disconnect()
        } catch (_: Throwable) {}
        try {
            mockWebServer.shutdown()
        } catch (_: Throwable) {}
    }

    @Test
    fun testInitialStateIsDisconnected() {
        assertEquals(NetworkTransport.ConnectionState.Disconnected, transport.getState())
    }

    @Test
    fun testSuccessfulConnectionAndMessageEcho() {
        val serverReceivedLatch = CountDownLatch(1)
        val clientReceivedLatch = CountDownLatch(1)
        var receivedTextOnClient: String? = null

        val serverListener = object : WebSocketListener() {
            override fun onMessage(webSocket: WebSocket, text: String) {
                serverReceivedLatch.countDown()
                // Echo message back to client
                webSocket.send("Echo: $text")
            }
        }

        mockWebServer.enqueue(MockResponse().withWebSocketUpgrade(serverListener))

        val connectedLatch = CountDownLatch(1)
        transport.addListener(object : NetworkTransport.Listener {
            override fun onStateChanged(newState: NetworkTransport.ConnectionState) {
                if (newState is NetworkTransport.ConnectionState.Connected) {
                    connectedLatch.countDown()
                }
            }

            override fun onMessageReceived(text: String) {
                receivedTextOnClient = text
                clientReceivedLatch.countDown()
            }
        })

        val wsUrl = mockWebServer.url("/ws/v1/connect").toString()
        transport.connect(wsUrl)

        assertTrue(connectedLatch.await(5, TimeUnit.SECONDS), "Client must transition to Connected state")
        val state = transport.getState()
        assertTrue(state is NetworkTransport.ConnectionState.Connected)

        // Send test message from client
        val sent = transport.send("Hello VPS")
        assertTrue(sent, "Message should be sent successfully")

        assertTrue(serverReceivedLatch.await(5, TimeUnit.SECONDS), "Server must receive message")
        assertTrue(clientReceivedLatch.await(5, TimeUnit.SECONDS), "Client must receive echoed message")
        assertEquals("Echo: Hello VPS", receivedTextOnClient)
    }

    @Test
    fun testCleanDisconnect() {
        mockWebServer.enqueue(MockResponse().withWebSocketUpgrade(object : WebSocketListener() {}))

        val connectedLatch = CountDownLatch(1)
        val disconnectedLatch = CountDownLatch(1)

        transport.addListener(object : NetworkTransport.Listener {
            override fun onStateChanged(newState: NetworkTransport.ConnectionState) {
                if (newState is NetworkTransport.ConnectionState.Connected) {
                    connectedLatch.countDown()
                } else if (newState is NetworkTransport.ConnectionState.Disconnected) {
                    disconnectedLatch.countDown()
                }
            }
        })

        transport.connect(mockWebServer.url("/ws/v1/connect").toString())
        assertTrue(connectedLatch.await(5, TimeUnit.SECONDS))

        transport.disconnect()
        assertEquals(NetworkTransport.ConnectionState.Disconnected, transport.getState())
    }

    @Test
    fun testUnreachableServerTriggersErrorAndStateTransition() {
        val errorLatch = CountDownLatch(1)
        var capturedError: Throwable? = null

        transport.addListener(object : NetworkTransport.Listener {
            override fun onError(error: Throwable) {
                capturedError = error
                errorLatch.countDown()
            }
        })

        // Connect to a closed port / non-existent server
        transport.connect("ws://127.0.0.1:54321/ws/nonexistent")

        assertTrue(errorLatch.await(5, TimeUnit.SECONDS), "Error callback must be triggered")
        assertNotNull(capturedError)

        // State machine must reflect either Reconnecting or Disconnected, never hang in Connecting
        val state = transport.getState()
        assertTrue(
            state is NetworkTransport.ConnectionState.Reconnecting ||
            state is NetworkTransport.ConnectionState.Disconnected ||
            state is NetworkTransport.ConnectionState.Error,
            "State machine must not hang in ambiguous state: $state"
        )
    }
}

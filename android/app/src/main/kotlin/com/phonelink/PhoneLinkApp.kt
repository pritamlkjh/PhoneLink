package com.phonelink

import android.app.Application

class PhoneLinkApp : Application() {
    companion object {
        const val VERSION = "1.0.0"
        const val NOTIFICATION_CHANNEL_ID = "phonelink_connection_channel"
    }

    override fun onCreate() {
        super.onCreate()
    }
}

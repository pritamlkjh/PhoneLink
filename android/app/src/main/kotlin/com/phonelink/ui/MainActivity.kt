package com.phonelink.ui

import android.os.Bundle
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.phonelink.PhoneLinkApp
import com.phonelink.R

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val textView = TextView(this).apply {
            text = "PhoneLink v${PhoneLinkApp.VERSION}\nStatus: Ready"
            textSize = 18f
            setPadding(48, 48, 48, 48)
        }
        setContentView(textView)
    }
}

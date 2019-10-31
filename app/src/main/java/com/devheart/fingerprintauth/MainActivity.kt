package com.devheart.fingerprintauth

import android.os.Build
import android.os.Bundle
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.Observer
import com.devheart.fingerprintauth.fingerprint.FingerprintAuth

class MainActivity : AppCompatActivity() {

    private lateinit var mFingerprint: FingerprintAuth

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            mFingerprint = FingerprintAuth(this)
            mFingerprint.initAuth()
            mFingerprint.authenticationResponse.observe(this, Observer {
                Toast.makeText(this, it, Toast.LENGTH_LONG).show()
            })
        }
    }
}

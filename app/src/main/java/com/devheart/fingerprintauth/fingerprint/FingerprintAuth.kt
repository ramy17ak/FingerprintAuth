package com.devheart.fingerprintauth.fingerprint

import android.content.Context
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.lifecycle.MutableLiveData

@RequiresApi(Build.VERSION_CODES.M)
class FingerprintAuth(private val pContext: Context) : FingerprintManager.AuthenticationCallback() {

    private lateinit var cancellationSignal: CancellationSignal
    private val mFingerprintTools: FingerprintTools by lazy { FingerprintTools(pContext) }
    val authenticationResponse: MutableLiveData<String> = MutableLiveData()

    fun initAuth() {
        cancellationSignal = CancellationSignal()
        mFingerprintTools.initFingerprint(cancellationSignal, this)
    }

    override fun onAuthenticationError(pErrMsgId: Int, pErrString: CharSequence) {
        cancellationSignal.cancel()
        authenticationResponse.value = "Authentication error\n$pErrString"
    }

    override fun onAuthenticationHelp(pHelpMsgId: Int, pHelpString: CharSequence) {
        cancellationSignal.cancel()
        authenticationResponse.value = "Authentication help\n$pHelpString"
    }

    override fun onAuthenticationFailed() {
        cancellationSignal.cancel()
        authenticationResponse.value = "Authentication failed."
    }

    override fun onAuthenticationSucceeded(pResult: FingerprintManager.AuthenticationResult) {
        cancellationSignal.cancel()
        authenticationResponse.value = "Authentication Succeeded."
    }

}
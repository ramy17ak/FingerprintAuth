package com.devheart.fingerprintauth.fingerprint

import android.Manifest
import android.app.KeyguardManager
import android.content.Context
import android.content.pm.PackageManager
import android.hardware.fingerprint.FingerprintManager
import android.os.Build
import android.os.CancellationSignal
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.widget.Toast
import androidx.annotation.RequiresApi
import androidx.core.app.ActivityCompat
import java.io.IOException
import java.security.*
import java.security.cert.CertificateException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.NoSuchPaddingException
import javax.crypto.SecretKey

class FingerprintTools(pContext: Context) {

    private lateinit var fingerprintManager: FingerprintManager
    private lateinit var keyguardManager: KeyguardManager
    private lateinit var keyStore: KeyStore
    private lateinit var keyGenerator: KeyGenerator
    private lateinit var cipher: Cipher
    private lateinit var cryptoObject: FingerprintManager.CryptoObject
    private val KEY_NAME = "Fingerprint_key"
    private val mContext: Context = pContext

    @RequiresApi(Build.VERSION_CODES.M)
    fun initFingerprint(pCancellationSignal: CancellationSignal, pCallback: FingerprintManager.AuthenticationCallback):Boolean {
          if (checkFingerprint()) {
            generateKey()
            if (initCipher()) {
                cipher.let {
                    cryptoObject = FingerprintManager.CryptoObject(it)
                    startAuth(pCancellationSignal, pCallback)
                }
            }
              return true
        }
        return false
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun startAuth(pCancellationSignal: CancellationSignal, pCallback: FingerprintManager.AuthenticationCallback) {
        if (ActivityCompat.checkSelfPermission(mContext, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(mContext, "Fingerprint Permission not enabled", Toast.LENGTH_LONG).show()
            return
        }
        fingerprintManager.authenticate(cryptoObject, pCancellationSignal, 0, pCallback, null)
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun checkFingerprint(): Boolean {
        keyguardManager = mContext.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        fingerprintManager = mContext.getSystemService(Context.FINGERPRINT_SERVICE) as FingerprintManager
        if (!keyguardManager.isKeyguardSecure) {
            Toast.makeText(mContext, "Lock screen security not enabled", Toast.LENGTH_LONG).show()
            return false
        }

        if (ActivityCompat.checkSelfPermission(mContext, Manifest.permission.USE_FINGERPRINT) != PackageManager.PERMISSION_GRANTED) {
            Toast.makeText(mContext, "Fingerprint Permission not enabled", Toast.LENGTH_LONG).show()
            return false
        }

        if (!fingerprintManager.hasEnrolledFingerprints()) {
            Toast.makeText(mContext, "No fingerprint registered, please register", Toast.LENGTH_LONG).show()
            return false
        }
        return true
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun generateKey() {
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore")
        } catch (e: Exception) {
            e.printStackTrace()
        }

        try {
            keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        } catch (e: Exception) {
            when (e) {
                is NoSuchAlgorithmException,
                is NoSuchProviderException -> { throw RuntimeException("Failed to get KeyGenerator instance", e) }
            }
        }

        try {
            keyStore.load(null)
            keyGenerator.init(KeyGenParameterSpec.Builder(KEY_NAME, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build()
            )
            keyGenerator.generateKey()
        } catch (e: Exception) {
            when (e) {
                is NoSuchAlgorithmException,
                is InvalidAlgorithmParameterException,
                is CertificateException,
                is IOException -> { throw RuntimeException(e) }
            }
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun initCipher(): Boolean {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7)
        }catch (e: Exception) {
            when (e) {
                is NoSuchAlgorithmException,
                is NoSuchPaddingException -> { throw RuntimeException("Failed to get Cipher", e) }
            }
        }

        try {
            keyStore.load(null)
            val key = keyStore.getKey(KEY_NAME, null) as SecretKey
            cipher.init(Cipher.ENCRYPT_MODE, key)
            return true
        }catch (e: Exception) {
            when (e) {
                is KeyStoreException,
                is UnrecoverableKeyException,
                is CertificateException,
                is IOException,
                is InvalidKeyException-> { throw RuntimeException("Failed to init Cipher", e) }
                is KeyPermanentlyInvalidatedException -> { return false }
            }
        }
        return false
    }
}
package com.sepehr.ikev2.vpn

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Ikev2VpnProfile
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnManager
import android.net.VpnProfileState
import android.net.eap.EapSessionConfig
import android.net.ipsec.ike.ChildSaProposal
import android.net.ipsec.ike.IkeFqdnIdentification
import android.net.ipsec.ike.IkeSaProposal
import android.net.ipsec.ike.IkeSessionParams
import android.net.ipsec.ike.IkeTunnelConnectionParams
import android.net.ipsec.ike.SaProposal
import android.net.ipsec.ike.TunnelModeChildSessionParams
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.system.OsConstants
import androidx.annotation.RequiresApi
import com.sepehr.ikev2.data.SecretTunnelSpec
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.io.ByteArrayInputStream
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

enum class VpnConnectionState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR
}

class Ikev2VpnController(private val appContext: Context) {

    private val vpnManager: VpnManager? = appContext.getSystemService(VpnManager::class.java)
    private val connectivityManager: ConnectivityManager? =
        appContext.getSystemService(ConnectivityManager::class.java)
    private val mainHandler = Handler(Looper.getMainLooper())

    private val _state = MutableStateFlow(VpnConnectionState.DISCONNECTED)
    val state: StateFlow<VpnConnectionState> = _state.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private var pendingStartAfterConsent = false
    private var connectAttemptTimestampMs = 0L

    private val timeoutRunnable = Runnable {
        if (_state.value == VpnConnectionState.CONNECTING) {
            runCatching { vpnManager?.stopProvisionedVpnProfile() }
            _state.value = VpnConnectionState.ERROR
            _errorMessage.value = "پاسخی از تونل IKEv2 دریافت نشد؛ سرور دیگری را امتحان کنید"
        }
    }

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val caps = connectivityManager?.getNetworkCapabilities(network)
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) {
                cancelTimeout()
                _state.value = VpnConnectionState.CONNECTED
                _errorMessage.value = null
            }
        }

        override fun onLost(network: Network) {
            if (!hasActiveVpnTransport() && _state.value == VpnConnectionState.CONNECTED) {
                _state.value = VpnConnectionState.DISCONNECTED
            }
        }
    }

    private val vpnEventReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
            if (intent?.action != VpnManager.ACTION_VPN_MANAGER_EVENT) return
            val categories = intent.categories ?: emptySet()
            val errorClass = intent.getIntExtra(VpnManager.EXTRA_ERROR_CLASS, -1)
            val errorCode = intent.getIntExtra(VpnManager.EXTRA_ERROR_CODE, -1)

            when {
                categories.contains(VpnManager.CATEGORY_EVENT_DEACTIVATED_BY_USER) -> {
                    cancelTimeout()
                    _state.value = VpnConnectionState.DISCONNECTED
                    _errorMessage.value = null
                }
                categories.contains(VpnManager.CATEGORY_EVENT_IKE_ERROR) -> {
                    if (errorClass == VpnManager.ERROR_CLASS_NOT_RECOVERABLE ||
                        _state.value == VpnConnectionState.CONNECTING
                    ) {
                        cancelTimeout()
                        runCatching { vpnManager?.stopProvisionedVpnProfile() }
                        _state.value = VpnConnectionState.ERROR
                        _errorMessage.value = if (errorCode != -1) {
                            "خطای مذاکره یا احراز هویت IKEv2 (کد $errorCode)"
                        } else {
                            "خطای مذاکره IKEv2 یا گواهی/احراز هویت سرور"
                        }
                    }
                }
                categories.contains(VpnManager.CATEGORY_EVENT_NETWORK_ERROR) -> {
                    if (errorClass == VpnManager.ERROR_CLASS_NOT_RECOVERABLE ||
                        _state.value == VpnConnectionState.CONNECTING
                    ) {
                        cancelTimeout()
                        runCatching { vpnManager?.stopProvisionedVpnProfile() }
                        _state.value = VpnConnectionState.ERROR
                        _errorMessage.value = when (errorCode) {
                            VpnManager.ERROR_CODE_NETWORK_UNKNOWN_HOST -> "خطای DNS یا عدم شناسایی میزبان سرور"
                            VpnManager.ERROR_CODE_NETWORK_PROTOCOL_TIMEOUT -> "پاسخی از سرور IKEv2 دریافت نشد (تایم‌اوت)"
                            VpnManager.ERROR_CODE_NETWORK_LOST,
                            VpnManager.ERROR_CODE_NETWORK_IO -> "اختلال یا قطع ارتباط شبکه هنگام برقراری تونل"
                            else -> "خطای شبکه هنگام برقراری تونل IKEv2"
                        }
                    }
                }
            }
        }
    }

    init {
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        runCatching {
            connectivityManager?.registerNetworkCallback(request, networkCallback)
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val filter = IntentFilter(VpnManager.ACTION_VPN_MANAGER_EVENT).apply {
                addCategory(VpnManager.CATEGORY_EVENT_IKE_ERROR)
                addCategory(VpnManager.CATEGORY_EVENT_NETWORK_ERROR)
                addCategory(VpnManager.CATEGORY_EVENT_DEACTIVATED_BY_USER)
                addCategory(VpnManager.CATEGORY_EVENT_ALWAYS_ON_STATE_CHANGED)
            }
            runCatching {
                appContext.registerReceiver(vpnEventReceiver, filter, Context.RECEIVER_EXPORTED)
            }
        }

        syncConnectionState()
    }

    private fun hasActiveVpnTransport(): Boolean {
        val cm = connectivityManager ?: return false
        val active = cm.activeNetwork
        if (active != null) {
            val caps = cm.getNetworkCapabilities(active)
            if (caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) return true
        }
        @Suppress("DEPRECATION")
        return cm.allNetworks.any { net ->
            val caps = cm.getNetworkCapabilities(net)
            caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        }
    }

    /**
     * Synchronizes UI state with the genuine OS VPN tunnel state so the app
     * never reports CONNECTED unless the IPsec tunnel is actually established.
     */
    fun syncConnectionState() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val profileState = runCatching { vpnManager?.provisionedVpnProfileState }.getOrNull()
            if (profileState != null) {
                when (profileState.state) {
                    VpnProfileState.STATE_CONNECTED -> {
                        cancelTimeout()
                        _state.value = VpnConnectionState.CONNECTED
                        _errorMessage.value = null
                        return
                    }
                    VpnProfileState.STATE_FAILED -> {
                        cancelTimeout()
                        _state.value = VpnConnectionState.ERROR
                        if (_errorMessage.value.isNullOrBlank()) {
                            _errorMessage.value = "برقراری تونل IKEv2 ناموفق بود"
                        }
                        return
                    }
                    VpnProfileState.STATE_CONNECTING -> {
                        if (_state.value != VpnConnectionState.CONNECTING) {
                            _state.value = VpnConnectionState.CONNECTING
                        }
                        return
                    }
                    VpnProfileState.STATE_DISCONNECTED -> {
                        val elapsed = System.currentTimeMillis() - connectAttemptTimestampMs
                        if (_state.value == VpnConnectionState.CONNECTED ||
                            (_state.value == VpnConnectionState.CONNECTING && elapsed > 3500L)
                        ) {
                            if (!hasActiveVpnTransport()) {
                                cancelTimeout()
                                if (_state.value == VpnConnectionState.CONNECTING) {
                                    _state.value = VpnConnectionState.ERROR
                                    _errorMessage.value = "اتصال توسط سرور IKEv2 رد شد یا بسته شد"
                                } else {
                                    _state.value = VpnConnectionState.DISCONNECTED
                                }
                            }
                        }
                        return
                    }
                }
            }
        }

        if (hasActiveVpnTransport()) {
            cancelTimeout()
            _state.value = VpnConnectionState.CONNECTED
            _errorMessage.value = null
        } else if (_state.value == VpnConnectionState.CONNECTED) {
            _state.value = VpnConnectionState.DISCONNECTED
        }
    }

    /**
     * Builds a native Android Ikev2VpnProfile:
     * - API 33+: Uses IkeTunnelConnectionParams so ServerHostname = IP and Remote ID (IDr) = Domain!
     * - API 30-32: Uses domain as serverAddr & username as identity so Remote ID matches TLS SAN.
     */
    fun connect(spec: SecretTunnelSpec): Intent? {
        return try {
            cancelTimeout()
            _errorMessage.value = null
            _state.value = VpnConnectionState.CONNECTING
            connectAttemptTimestampMs = System.currentTimeMillis()

            val caCert = parsePemCertificate(spec.caCert)
            val profile = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                buildApi33Profile(spec, caCert)
            } else {
                Ikev2VpnProfile.Builder(spec.remoteId ?: spec.serverIdentity, spec.ikeUsername)
                    .setAuthUsernamePassword(spec.ikeUsername, spec.ikePassword, caCert)
                    .setBypassable(false)
                    .setMetered(false)
                    .build()
            }

            val manager = vpnManager ?: run {
                cancelTimeout()
                _state.value = VpnConnectionState.ERROR
                _errorMessage.value = "سرویس VPN در این دستگاه در دسترس نیست"
                return null
            }

            val consentIntent = manager.provisionVpnProfile(profile)
            if (consentIntent != null) {
                pendingStartAfterConsent = true
                consentIntent
            } else {
                startProvisionedTunnel()
                null
            }
        } catch (e: Exception) {
            cancelTimeout()
            _state.value = VpnConnectionState.ERROR
            _errorMessage.value = "پیکربندی تونل IKEv2 با خطا مواجه شد"
            null
        }
    }

    private fun parsePemCertificate(pem: String?): X509Certificate? {
        if (pem.isNullOrBlank()) return null
        return runCatching {
            val factory = CertificateFactory.getInstance("X.509")
            ByteArrayInputStream(pem.trim().toByteArray(Charsets.UTF_8)).use { stream ->
                factory.generateCertificate(stream) as? X509Certificate
            }
        }.getOrNull()
    }

    @RequiresApi(Build.VERSION_CODES.TIRAMISU)
    private fun buildApi33Profile(spec: SecretTunnelSpec, caCert: X509Certificate?): Ikev2VpnProfile {
        val ikeProposalGcm = IkeSaProposal.Builder()
            .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16, SaProposal.KEY_LEN_AES_256)
            .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16, SaProposal.KEY_LEN_AES_128)
            .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_SHA2_256)
            .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_SHA2_384)
            .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_SHA2_512)
            .addDhGroup(SaProposal.DH_GROUP_2048_BIT_MODP)
            .addDhGroup(SaProposal.DH_GROUP_CURVE_25519)
            .addDhGroup(SaProposal.DH_GROUP_3072_BIT_MODP)
            .addDhGroup(SaProposal.DH_GROUP_4096_BIT_MODP)
            .addDhGroup(SaProposal.DH_GROUP_1536_BIT_MODP)
            .build()

        val ikeProposalCbc = IkeSaProposal.Builder()
            .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_256)
            .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_128)
            .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128)
            .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_384_192)
            .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_512_256)
            .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
            .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_SHA2_256)
            .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_SHA2_384)
            .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_SHA2_512)
            .addPseudorandomFunction(SaProposal.PSEUDORANDOM_FUNCTION_HMAC_SHA1)
            .addDhGroup(SaProposal.DH_GROUP_2048_BIT_MODP)
            .addDhGroup(SaProposal.DH_GROUP_1536_BIT_MODP)
            .addDhGroup(SaProposal.DH_GROUP_CURVE_25519)
            .addDhGroup(SaProposal.DH_GROUP_3072_BIT_MODP)
            .addDhGroup(SaProposal.DH_GROUP_4096_BIT_MODP)
            .build()

        val childProposalGcm = ChildSaProposal.Builder()
            .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16, SaProposal.KEY_LEN_AES_256)
            .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_GCM_16, SaProposal.KEY_LEN_AES_128)
            .build()

        val childProposalCbc = ChildSaProposal.Builder()
            .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_256)
            .addEncryptionAlgorithm(SaProposal.ENCRYPTION_ALGORITHM_AES_CBC, SaProposal.KEY_LEN_AES_128)
            .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_256_128)
            .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_384_192)
            .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA2_512_256)
            .addIntegrityAlgorithm(SaProposal.INTEGRITY_ALGORITHM_HMAC_SHA1_96)
            .build()

        val eapConfig = EapSessionConfig.Builder()
            .setEapMsChapV2Config(spec.ikeUsername.trim(), spec.ikePassword)
            .build()

        val expectedRemoteId = (spec.remoteId ?: spec.serverIdentity).trim()

        val ikeParams = IkeSessionParams.Builder()
            .setServerHostname(spec.serverHost.trim())
            .setRemoteIdentification(IkeFqdnIdentification(expectedRemoteId))
            .setLocalIdentification(IkeFqdnIdentification(spec.ikeUsername.trim()))
            // Accept responder IDs returned by CDN/wildcard gateways (e.g., *.nodes.gen4.ninja / *.cg-dialup.net)
            // while still validating the server's X.509 certificate chain against trusted CAs.
            .addIkeOption(IkeSessionParams.IKE_OPTION_ACCEPT_ANY_REMOTE_ID)
            .addIkeOption(IkeSessionParams.IKE_OPTION_MOBIKE)
            .addIkeSaProposal(ikeProposalGcm)
            .addIkeSaProposal(ikeProposalCbc)
            .setAuthEap(caCert, eapConfig)
            .setDpdDelaySeconds(30)
            .setNattKeepAliveDelaySeconds(20)
            .build()

        val childParams = TunnelModeChildSessionParams.Builder()
            .addChildSaProposal(childProposalGcm)
            .addChildSaProposal(childProposalCbc)
            .addInternalAddressRequest(OsConstants.AF_INET)
            .addInternalDnsServerRequest(OsConstants.AF_INET)
            .build()

        val tunnelParams = IkeTunnelConnectionParams(ikeParams, childParams)

        return Ikev2VpnProfile.Builder(tunnelParams)
            .setBypassable(false)
            .setMetered(false)
            .setMaxMtu(1360)
            .build()
    }

    fun onConsentResult(granted: Boolean) {
        if (granted && pendingStartAfterConsent) {
            pendingStartAfterConsent = false
            startProvisionedTunnel()
        } else {
            pendingStartAfterConsent = false
            cancelTimeout()
            _state.value = VpnConnectionState.DISCONNECTED
            _errorMessage.value = "مجوز اتصال VPN توسط کاربر تایید نشد"
        }
    }

    private fun startProvisionedTunnel() {
        try {
            val manager = vpnManager ?: throw IllegalStateException("VpnManager unavailable")
            connectAttemptTimestampMs = System.currentTimeMillis()
            _state.value = VpnConnectionState.CONNECTING
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                manager.startProvisionedVpnProfileSession()
            } else {
                @Suppress("DEPRECATION")
                manager.startProvisionedVpnProfile()
            }
            mainHandler.removeCallbacks(timeoutRunnable)
            mainHandler.postDelayed(timeoutRunnable, 18000L)
        } catch (e: Exception) {
            cancelTimeout()
            _state.value = VpnConnectionState.ERROR
            _errorMessage.value = "امکان شروع سرویس IKEv2 وجود ندارد"
        }
    }

    fun disconnect() {
        cancelTimeout()
        pendingStartAfterConsent = false
        try {
            vpnManager?.stopProvisionedVpnProfile()
        } finally {
            _state.value = VpnConnectionState.DISCONNECTED
            _errorMessage.value = null
        }
    }

    private fun cancelTimeout() {
        mainHandler.removeCallbacks(timeoutRunnable)
    }

    fun release() {
        cancelTimeout()
        runCatching {
            connectivityManager?.unregisterNetworkCallback(networkCallback)
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            runCatching {
                appContext.unregisterReceiver(vpnEventReceiver)
            }
        }
    }
}

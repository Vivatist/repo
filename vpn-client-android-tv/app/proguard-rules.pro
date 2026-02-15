# ProGuard rules for NovaVPN TV

# Keep crypto classes
-keep class org.bouncycastle.** { *; }

# Keep data models
-keep class com.novavpn.tv.domain.model.** { *; }

# Keep VPN service
-keep class com.novavpn.tv.service.NovaVpnService { *; }

# Keep boot receiver
-keep class com.novavpn.tv.receiver.BootReceiver { *; }

# ProGuard rules for NovaVPN TV

# Keep crypto classes
-keep class org.bouncycastle.** { *; }

# BouncyCastle ссылается на javax.naming (LDAP), которого нет в Android.
# Эти классы не используются в нашем коде — безопасно игнорируем.
-dontwarn javax.naming.**

# Keep data models
-keep class com.novavpn.tv.domain.model.** { *; }

# Keep VPN service
-keep class com.novavpn.tv.service.NovaVpnService { *; }

# Keep boot receiver
-keep class com.novavpn.tv.receiver.BootReceiver { *; }

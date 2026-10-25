package com.netaver.dns.log

/**
 * Immutable log entry models.
 *
 * All fields are @JvmField so the still-Java modules (DnsVpnService, proxies,
 * fragments) keep their direct field reads/writes compiling unchanged.
 */
class Entries private constructor() {

    // @JvmOverloads: the still-Java modules construct these with the
    // original arg counts (8 for DnsEntry, 9 for ConnEntry, 1 for AppStat);
    // Kotlin default args are invisible to Java without it.
    data class DnsEntry @JvmOverloads constructor(
        @JvmField val time: Long,
        @JvmField val domain: String,
        @JvmField val qtype: String,
        @JvmField val app: String,
        @JvmField val uid: Int,
        @JvmField val blocked: Boolean,
        @JvmField val latencyMs: Long,
        @JvmField val resolvedIp: String, // never null: callers coalesce (Java ctor did resolvedIp == null ? "" : resolvedIp)
        @JvmField @Volatile var countryCode: String = "",
        @JvmField @Volatile var matchInfo: String = "", // e.g. "Custom rule", "Hagezi Pro", "Upstream 1.1.1.1"
        @JvmField @Volatile var isBypass: Boolean = false // bypass attempt (e.g. hardcoded DoT server)
    ) {
        /** True when the answer was served from the local DNS cache
         *  ("Cache", "Cache (offline)", or "Cache (stale)"). */
        val fromCache: Boolean
            get() = matchInfo.startsWith("Cache")
    }

    data class ConnEntry @JvmOverloads constructor(
        @JvmField val time: Long,
        @JvmField val app: String,
        @JvmField val uid: Int,
        @JvmField val proto: String, // TCP/UDP
        @JvmField val dest: String, // ip:port
        @JvmField val bytesUp: Long,
        @JvmField val bytesDown: Long,
        @JvmField val durationMs: Long,
        @JvmField val blocked: Boolean, // blocked by firewall
        @JvmField var countryCode: String = "" // filled async by GeoIp
    )

    /** Aggregated per-app stats derived from the logs. */
    data class AppStat @JvmOverloads constructor(
        @JvmField val app: String,
        @JvmField var uid: Int = -1,
        @JvmField var queries: Long = 0,
        @JvmField var blocked: Long = 0,
        @JvmField var conns: Long = 0,
        @JvmField var bytesUp: Long = 0,
        @JvmField var bytesDown: Long = 0,
        /** True when this row comes from the installed-packages list (no traffic yet). */
        @JvmField var installedOnly: Boolean = false
    )
}

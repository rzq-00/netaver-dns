package com.netaver.dns.util

/**
 * Catalog of well-known public DNS providers for the Upstream tab.
 * Addresses follow AdGuard's "Known DNS Providers" knowledge base.
 * A variant is one selectable flavor of a provider (Standard, Family, ...);
 * protocols are the transport choices the app already supports (DoT/DoH/plain IP).
 */
object ProviderCatalog {

    const val PROTO_DOT = 1
    const val PROTO_DOH = 2
    const val PROTO_IPV4 = 0

    class Variant(
        val name: String,          // variant label as the provider calls it ("" = only flavor)
        val dotHost: String,       // DoT hostname ("" = not offered)
        val dohUrl: String,        // full DoH URL ("" = not offered)
        val ips: List<String>      // plain IPs, primary first (empty = not offered)
    ) {
        fun protocols(): List<Int> {
            val out = ArrayList<Int>(3)
            if (dotHost.isNotEmpty()) out.add(PROTO_DOT)
            if (dohUrl.isNotEmpty()) out.add(PROTO_DOH)
            if (ips.isNotEmpty()) out.add(PROTO_IPV4)
            return out
        }

        /** Address this variant yields for a protocol, in stored-spec form. */
        fun specFor(proto: Int): String = when (proto) {
            PROTO_DOT -> "tls://$dotHost"
            PROTO_DOH -> dohUrl
            else -> ips.firstOrNull() ?: ""
        }
    }

    class Provider(
        val name: String,
        val traitRes: Int,         // string resource: one-line description
        val variants: List<Variant>
    )

    val providers: List<Provider> = listOf(
        Provider("Cloudflare", com.netaver.dns.R.string.trait_cloudflare, listOf(
            Variant("Standard", "one.one.one.one", "https://cloudflare-dns.com/dns-query",
                listOf("1.1.1.1", "1.0.0.1")),
            Variant("Malware", "security.cloudflare-dns.com", "https://security.cloudflare-dns.com/dns-query",
                listOf("1.1.1.2", "1.0.0.2")),
            Variant("Family", "family.cloudflare-dns.com", "https://family.cloudflare-dns.com/dns-query",
                listOf("1.1.1.3", "1.0.0.3"))
        )),
        Provider("Google", com.netaver.dns.R.string.trait_google, listOf(
            Variant("", "dns.google", "https://dns.google/dns-query",
                listOf("8.8.8.8", "8.8.4.4"))
        )),
        Provider("Quad9", com.netaver.dns.R.string.trait_quad9, listOf(
            Variant("Secured", "dns.quad9.net", "https://dns.quad9.net/dns-query",
                listOf("9.9.9.9", "149.112.112.112")),
            Variant("Unsecured", "dns10.quad9.net", "https://dns10.quad9.net/dns-query",
                listOf("9.9.9.10", "149.112.112.10")),
            Variant("ECS", "dns11.quad9.net", "https://dns11.quad9.net/dns-query",
                listOf("9.9.9.11", "149.112.112.11"))
        )),
        Provider("AdGuard", com.netaver.dns.R.string.trait_adguard, listOf(
            Variant("Default", "dns.adguard-dns.com", "https://dns.adguard-dns.com/dns-query",
                listOf("94.140.14.14", "94.140.15.15")),
            Variant("Family", "family.adguard-dns.com", "https://family.adguard-dns.com/dns-query",
                listOf("94.140.14.15", "94.140.15.16")),
            Variant("Unfiltered", "unfiltered.adguard-dns.com", "https://unfiltered.adguard-dns.com/dns-query",
                listOf("94.140.14.140", "94.140.14.141"))
        )),
        Provider("NextDNS", com.netaver.dns.R.string.trait_nextdns, listOf(
            Variant("Anycast", "anycast.dns.nextdns.io", "https://anycast.dns.nextdns.io",
                emptyList()),
            Variant("Ultra-low latency", "dns.nextdns.io", "https://dns.nextdns.io",
                emptyList())
        )),
        Provider("CleanBrowsing", com.netaver.dns.R.string.trait_cleanbrowsing, listOf(
            Variant("Family", "family-filter-dns.cleanbrowsing.org", "https://doh.cleanbrowsing.org/doh/family-filter/",
                listOf("185.228.168.168", "185.228.169.168")),
            Variant("Adult", "adult-filter-dns.cleanbrowsing.org", "https://doh.cleanbrowsing.org/doh/adult-filter/",
                listOf("185.228.168.10", "185.228.169.11")),
            Variant("Security", "security-filter-dns.cleanbrowsing.org", "https://doh.cleanbrowsing.org/doh/security-filter/",
                listOf("185.228.168.9", "185.228.169.9"))
        )),
        Provider("BebasDNS", com.netaver.dns.R.string.trait_bebasdns, listOf(
            Variant("Default", "dns.bebasid.com", "https://dns.bebasid.com/dns-query",
                emptyList()),
            Variant("Family", "internetsehat.bebasid.com", "https://internetsehat.bebasid.com/dns-query",
                emptyList()),
            Variant("Security", "antivirus.bebasid.com", "https://antivirus.bebasid.com/dns-query",
                emptyList()),
            Variant("Unfiltered", "unfiltered.dns.bebasid.com", "https://dns.bebasid.com/unfiltered",
                emptyList())
        )),
        Provider("Ali DNS", com.netaver.dns.R.string.trait_alidns, listOf(
            Variant("", "dns.alidns.com", "https://dns.alidns.com/dns-query",
                listOf("223.5.5.5", "223.6.6.6"))
        ))
    )

    /** Display identity of a stored upstream spec. */
    class Identity(
        val providerName: String,
        val variantName: String,   // "" when the provider has a single flavor
        val proto: Int,            // effective protocol (PROTO_*); presets/bare follow the global pref
        val known: Boolean         // false = custom entry
    )

    private fun protoNameKey(proto: Int): String = when (proto) {
        PROTO_DOH -> "DoH"
        PROTO_IPV4 -> "IPv4"
        else -> "DoT"
    }

    /** Short chip text for an ACTIVE row: protocol only ("DoT", "DoH", "IPv4"). */
    fun chipText(id: Identity): String = protoNameKey(id.proto)

    /** Normalized match key for a URL-ish spec: scheme + host + significant path. */
    private fun urlKey(scheme: String, host: String, path: String): String {
        val p = if (path == "/dns-query" || path == "/") "" else path.trimEnd('/')
        return "$scheme://$host$p".lowercase()
    }

    /**
     * Resolve a stored spec to its catalog identity.
     * [globalProto] is Prefs.getProtocol() (1=DoT, 2=DoH) for presets and bare entries.
     */
    fun identify(spec: String, globalProto: Int): Identity {
        if (spec.startsWith("preset:")) {
            val w = spec.removePrefix("preset:").toIntOrNull() ?: 0
            return when (w) {
                1 -> Identity("Google", "", globalProto, true)
                2 -> Identity("Quad9", "Secured", globalProto, true)
                else -> Identity("Cloudflare", "Standard", globalProto, true)
            }
        }
        val s = Prefs.parseCustomUpstream(spec)
        if (!s.valid) return Identity("", "", globalProto, false)
        val host = s.host.lowercase()
        val proto = if (s.protoOverride >= 0) s.protoOverride else globalProto
        // scheme of the stored spec: 2=https (DoH), 1=tls (DoT), -1=bare
        for (p in providers) {
            for (v in p.variants) {
                if (s.protoOverride == PROTO_DOH && v.dohUrl.isNotEmpty()) {
                    val dv = Prefs.parseCustomUpstream(v.dohUrl)
                    if (urlKey("https", host, s.path) == urlKey("https", dv.host.lowercase(), dv.path)) {
                        return Identity(p.name, v.name, PROTO_DOH, true)
                    }
                }
                if (s.protoOverride == PROTO_DOT) {
                    if (host == v.dotHost.lowercase() || v.ips.any { it.equals(host, true) }) {
                        return Identity(p.name, v.name, PROTO_DOT, true)
                    }
                }
                if (s.protoOverride < 0) {
                    // bare IP or hostname: follows the global protocol
                    if (v.ips.any { it.equals(host, true) } || host == v.dotHost.lowercase()) {
                        return Identity(p.name, v.name, proto, true)
                    }
                }
            }
        }
        return Identity("", "", proto, false)
    }

    /**
     * U5: semantic endpoint identity of a spec, for duplicate detection.
     * Two spellings of the same server (preset:0 on DoT vs
     * tls://one.one.one.one, a catalog DoH URL vs preset:0 on DoH) must
     * map to one key. When the catalog recognizes the endpoint and the
     * port is the family default, the key is the catalog identity;
     * otherwise it is the normalized "host|port|family" of the parsed
     * spec (+ path for DoH, where the path distinguishes profiles).
     */
    fun endpointKey(spec: String, prefs: Prefs): String {
        val global = prefs.getProtocol() // 1=DoT, 2=DoH (legacy 0 coerced)
        if (spec.startsWith("preset:")) {
            val id = identify(spec, global)
            return "known|${id.providerName}|${id.variantName}|$global"
        }
        val s = Prefs.parseCustomUpstream(spec)
        if (!s.valid) return "invalid|$spec"
        val proto = if (s.protoOverride >= 0) s.protoOverride else global
        val defPort = when (proto) { 2 -> 443; 1 -> 853; else -> 53 }
        val port = if (s.port > 0) s.port else defPort
        if (port == defPort) {
            val id = identify(spec, global)
            if (id.known) return "known|${id.providerName}|${id.variantName}|$proto"
            // Preset spellings the catalog match can miss (DoH written
            // with the preset's TLS host or primary IP, e.g.
            // https://one.one.one.one/dns-query vs preset:0 on DoH).
            val hostLc = s.host.lowercase()
            for (w in 0..2) {
                if (hostLc == Prefs.upstreamTlsHost(w).lowercase() || hostLc == Prefs.upstreamIp(w)) {
                    val pid = identify("preset:$w", global)
                    return "known|${pid.providerName}|${pid.variantName}|$proto"
                }
            }
            // N5: a DoH URL written with ANY of a variant's IPs is the
            // same endpoint (e.g. https://8.8.4.4/dns-query is Google's
            // secondary) — identify() matches DoH by hostname/URL only,
            // so map IP spellings here just like its DoT branch does.
            if (proto == PROTO_DOH) {
                for (p in providers) {
                    for (v in p.variants) {
                        if (v.ips.any { it.equals(hostLc, true) }) {
                            return "known|${p.name}|${v.name}|$proto"
                        }
                    }
                }
            }
        }
        var host = s.host.lowercase()
        // a preset's primary IP and its TLS host are the same server
        for (w in 0..2) {
            if (host == Prefs.upstreamIp(w)) { host = Prefs.upstreamTlsHost(w); break }
        }
        return when (proto) {
            2 -> {
                val pth = s.path.lowercase()
                val suffix = if (pth == "/dns-query" || pth == "/" || pth.isEmpty()) ""
                    else pth.trimEnd('/')
                "$host|$port|doh$suffix"
            }
            1 -> "$host|$port|dot"
            else -> "$host|$port|plain"
        }
    }

    /** Secondary line for an ACTIVE row: the address as stored/effective. */
    fun addressLine(spec: String): String {
        if (spec.startsWith("preset:")) {
            val w = spec.removePrefix("preset:").toIntOrNull() ?: 0
            return "${Prefs.upstreamIp(w)} (${Prefs.upstreamTlsHost(w)})"
        }
        return spec
    }
}

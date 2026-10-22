package com.netaver.dns.util

import android.content.Context
import android.content.res.Configuration
import java.util.Locale

/** Per-app language override stored in Prefs: "" = follow system, "en", "in". */
object Lang {
    fun wrap(ctx: Context): Context {
        val code = try {
            Prefs(ctx).appLanguage()
        } catch (e: Exception) {
            ""
        }
        if (code.isEmpty()) return ctx
        val locale = Locale(code)
        Locale.setDefault(locale)
        val cfg = Configuration(ctx.resources.configuration)
        cfg.setLocale(locale)
        return ctx.createConfigurationContext(cfg)
    }
}

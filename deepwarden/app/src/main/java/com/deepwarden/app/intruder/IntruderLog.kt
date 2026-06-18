package com.deepwarden.app.intruder

import android.content.Context
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Records failed-unlock ("intruder") events. SharedPreferences so the
 * device-admin broadcast receiver can write synchronously and the UI can read.
 */
object IntruderLog {
    private const val FILE = "deepwarden_intruder"
    private const val KEY_COUNT = "fail_count"
    private const val KEY_EVENTS = "events"
    private const val MAX_EVENTS = 20

    private fun prefs(context: Context) =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun recordFailure(context: Context) {
        val p = prefs(context)
        val count = p.getInt(KEY_COUNT, 0) + 1
        val stamp = SimpleDateFormat("dd MMM, HH:mm:ss", Locale.getDefault()).format(Date())
        val events = (listOf(stamp) + recentEvents(context)).take(MAX_EVENTS)
        p.edit()
            .putInt(KEY_COUNT, count)
            .putString(KEY_EVENTS, events.joinToString("|"))
            .apply()
    }

    fun resetOnSuccess(context: Context) {
        // Keep history, just reset the consecutive-fail counter.
        prefs(context).edit().putInt(KEY_COUNT, 0).apply()
    }

    fun totalFailures(context: Context): Int = prefs(context).getInt(KEY_COUNT, 0)

    fun recentEvents(context: Context): List<String> =
        prefs(context).getString(KEY_EVENTS, "")?.split("|")?.filter { it.isNotBlank() } ?: emptyList()

    fun clear(context: Context) =
        prefs(context).edit().clear().apply()
}

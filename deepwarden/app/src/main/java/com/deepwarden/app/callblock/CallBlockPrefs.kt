package com.deepwarden.app.callblock

import android.content.Context

/**
 * Synchronous call-block config shared between the Settings UI and the
 * [DeepWardenCallScreeningService]. We use SharedPreferences (not DataStore)
 * deliberately: the screening callback must read the rules synchronously and
 * instantly, with no coroutine, the moment a call comes in.
 */
object CallBlockPrefs {
    private const val FILE = "deepwarden_callblock"
    private const val KEY_BLOCK_HIDDEN = "block_hidden"
    private const val KEY_BLOCK_NON_CONTACTS = "block_non_contacts"
    private const val KEY_BLOCKED = "blocked_numbers"

    private fun prefs(context: Context) =
        context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    fun blockHidden(context: Context): Boolean =
        prefs(context).getBoolean(KEY_BLOCK_HIDDEN, false)

    fun setBlockHidden(context: Context, value: Boolean) =
        prefs(context).edit().putBoolean(KEY_BLOCK_HIDDEN, value).apply()

    fun blockNonContacts(context: Context): Boolean =
        prefs(context).getBoolean(KEY_BLOCK_NON_CONTACTS, false)

    fun setBlockNonContacts(context: Context, value: Boolean) =
        prefs(context).edit().putBoolean(KEY_BLOCK_NON_CONTACTS, value).apply()

    fun blockedNumbers(context: Context): Set<String> =
        prefs(context).getStringSet(KEY_BLOCKED, emptySet())?.toSet() ?: emptySet()

    fun addBlocked(context: Context, number: String) {
        val clean = number.filter { it.isDigit() || it == '+' }
        if (clean.isBlank()) return
        val set = blockedNumbers(context).toMutableSet().apply { add(clean) }
        prefs(context).edit().putStringSet(KEY_BLOCKED, set).apply()
    }

    fun removeBlocked(context: Context, number: String) {
        val set = blockedNumbers(context).toMutableSet().apply { remove(number) }
        prefs(context).edit().putStringSet(KEY_BLOCKED, set).apply()
    }

    /** Normalised digit comparison so +91-98… and 098… still match a stored number. */
    fun isBlocked(context: Context, incoming: String?): Boolean {
        if (incoming == null) return blockHidden(context) // null handle == withheld/hidden
        val digits = incoming.filter { it.isDigit() }
        return blockedNumbers(context).any { stored ->
            val s = stored.filter { it.isDigit() }
            s.isNotEmpty() && (digits.endsWith(s) || s.endsWith(digits))
        }
    }
}

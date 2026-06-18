package com.deepwarden.app.callblock

import android.telecom.Call
import android.telecom.CallScreeningService

/**
 * Real call blocking via Android's official [CallScreeningService] API.
 *
 * Becomes active only when the user grants DeepWarden the "call screening"
 * role (requested from Settings). When an incoming call arrives, Android hands
 * us the call details; if it matches the user's block rules we reject it
 * silently. This is the supported, Play-compliant way to block calls — no root,
 * no shady permissions.
 */
class DeepWardenCallScreeningService : CallScreeningService() {

    override fun onScreenCall(callDetails: Call.Details) {
        if (callDetails.callDirection != Call.Details.DIRECTION_INCOMING) {
            respondToCall(callDetails, CallResponse.Builder().build())
            return
        }
        val number = callDetails.handle?.schemeSpecificPart
        val block = CallBlockPrefs.isBlocked(applicationContext, number)

        val response = CallResponse.Builder()
        if (block) {
            response.setDisallowCall(true)
            response.setRejectCall(true)
            response.setSkipCallLog(false)        // keep a record so the user sees it
            response.setSkipNotification(true)    // but don't ring/notify
        }
        respondToCall(callDetails, response.build())
    }
}

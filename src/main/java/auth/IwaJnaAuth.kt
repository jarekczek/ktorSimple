package auth

import com.sun.jna.platform.win32.*
import com.sun.jna.ptr.IntByReference
import io.ktor.application.Application
import io.ktor.application.ApplicationCallPipeline
import io.ktor.application.call
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.request.path
import io.ktor.response.respond
import io.ktor.response.respondText
import io.ktor.response.respondWrite
import io.ktor.util.decodeBase64
import io.ktor.util.encodeBase64

fun Application.interceptAndAuthenticateIWA() {
  intercept(ApplicationCallPipeline.Call) {
    var negResult: AcceptBytesResponse? = null
    if (context.request.path().equals("/jna")) {
      context.request.headers.forEach { s, l ->
        println("header $s: " + l.joinToString(","))
      }
      val authNegHeader = context.request.headers["Authorization"]?.replace("Negotiate", "")?.trim()
      println("authNegHeader: $authNegHeader")
      val authNegHeaderBytes = try {
        authNegHeader?.let { decodeBase64(it) }
      } catch(e: Exception) {
        println("impossible to decode $authNegHeader")
        null
      }
      if (authNegHeaderBytes == null) {
        context.response.headers.append("WWW-Authenticate", "Negotiate")
        println("requiring authentication")
      } else {
        println("received token bytes: " + authNegHeaderBytes.size)
        negResult = IwaJnaAuth.acceptBytes(authNegHeaderBytes)
        if (negResult.tokenBytes != null) {
          context.response.headers.append("WWW-Authenticate", "Negotiate " + encodeBase64(negResult.tokenBytes))
        }
        if (negResult.identity == null) {
          if (negResult.shouldContinue)
            println("requiring to continue authentication")
          else
            println("authentication failed")
        }
        else
          println("successfully authenticated ${negResult.identity}")
      }
      if (negResult?.identity == null) {
        call.respondText(negResult?.contextFlags ?: "", ContentType.Text.Plain, HttpStatusCode.Unauthorized)
      } else {
        call.respondText("Witaj " + negResult.identity, ContentType.Text.Plain, HttpStatusCode.OK)
      }
    }
  }
}


object IwaJnaAuth {
  val serverName = "jakis serwer"
  var ctx = ServerContext(serverName)

  fun acceptBytes(inputTokenBytes: ByteArray): AcceptBytesResponse {
    return ctx.acceptBytes(inputTokenBytes)
  }

  fun resetContext() {
    ctx = ServerContext(serverName)
  }

  private fun getIscFlagText(flag: Int): String? {
    val flagText = HashMap<Int, String>()
    fun registerFlag(name: String, value: Int) = flagText.put(value, name)
    registerFlag("ISC_RET_DELEGATE               ", 0x00000001)
    registerFlag("ISC_RET_MUTUAL_AUTH            ", 0x00000002)
    registerFlag("ISC_RET_REPLAY_DETECT          ", 0x00000004)
    registerFlag("ISC_RET_SEQUENCE_DETECT        ", 0x00000008)
    registerFlag("ISC_RET_CONFIDENTIALITY        ", 0x00000010)
    registerFlag("ISC_RET_USE_SESSION_KEY        ", 0x00000020)
    registerFlag("ISC_RET_USED_COLLECTED_CREDS   ", 0x00000040)
    registerFlag("ISC_RET_USED_SUPPLIED_CREDS    ", 0x00000080)
    registerFlag("ISC_RET_ALLOCATED_MEMORY       ", 0x00000100)
    registerFlag("ISC_RET_USED_DCE_STYLE         ", 0x00000200)
    registerFlag("ISC_RET_DATAGRAM               ", 0x00000400)
    registerFlag("ISC_RET_CONNECTION             ", 0x00000800)
    registerFlag("ISC_RET_INTERMEDIATE_RETURN    ", 0x00001000)
    registerFlag("ISC_RET_CALL_LEVEL             ", 0x00002000)
    registerFlag("ISC_RET_EXTENDED_ERROR         ", 0x00004000)
    registerFlag("ISC_RET_STREAM                 ", 0x00008000)
    registerFlag("ISC_RET_INTEGRITY              ", 0x00010000)
    registerFlag("ISC_RET_IDENTIFY               ", 0x00020000)
    registerFlag("ISC_RET_NULL_SESSION           ", 0x00040000)
    registerFlag("ISC_RET_MANUAL_CRED_VALIDATION ", 0x00080000)
    registerFlag("ISC_RET_RESERVED1              ", 0x00100000)
    registerFlag("ISC_RET_FRAGMENT_ONLY          ", 0x00200000)
    registerFlag("ISC_RET_FORWARD_CREDENTIALS    ", 0x00400000)
    registerFlag("ISC_RET_USED_HTTP_STYLE        ", 0x01000000)
    registerFlag("ISC_RET_NO_ADDITIONAL_TOKEN    ", 0x02000000) // *INTERNAL*
    registerFlag("ISC_RET_REAUTHENTICATION       ", 0x08000000) // *INTERNAL*
    registerFlag("ISC_RET_CONFIDENTIALITY_ONLY   ", 0x40000000) // honored by SPNEGO/Kerberos
    return flagText[flag]
  }

  private fun getAscFlagText(flag: Int): String? {
    val flagText = HashMap<Int, String>()
    fun registerFlag(name: String, value: Int) = flagText.put(value, name)
    registerFlag("ASC_RET_DELEGATE             ", 0x00000001)
    registerFlag("ASC_RET_MUTUAL_AUTH          ", 0x00000002)
    registerFlag("ASC_RET_REPLAY_DETECT        ", 0x00000004)
    registerFlag("ASC_RET_SEQUENCE_DETECT      ", 0x00000008)
    registerFlag("ASC_RET_CONFIDENTIALITY      ", 0x00000010)
    registerFlag("ASC_RET_USE_SESSION_KEY      ", 0x00000020)
    registerFlag("ASC_RET_SESSION_TICKET       ", 0x00000040)
    registerFlag("ASC_RET_ALLOCATED_MEMORY     ", 0x00000100)
    registerFlag("ASC_RET_USED_DCE_STYLE       ", 0x00000200)
    registerFlag("ASC_RET_DATAGRAM             ", 0x00000400)
    registerFlag("ASC_RET_CONNECTION           ", 0x00000800)
    registerFlag("unknown flag ASC_RET 0x1000  ", 0x00001000)
    registerFlag("ASC_RET_CALL_LEVEL           ", 0x00002000) // skipped 1000 to be like ISC_
    registerFlag("ASC_RET_THIRD_LEG_FAILED     ", 0x00004000)
    registerFlag("ASC_RET_EXTENDED_ERROR       ", 0x00008000)
    registerFlag("ASC_RET_STREAM               ", 0x00010000)
    registerFlag("ASC_RET_INTEGRITY            ", 0x00020000)
    registerFlag("ASC_RET_LICENSING            ", 0x00040000)
    registerFlag("ASC_RET_IDENTIFY             ", 0x00080000)
    registerFlag("ASC_RET_NULL_SESSION         ", 0x00100000)
    registerFlag("ASC_RET_ALLOW_NON_USER_LOGONS", 0x00200000)
    registerFlag("ASC_RET_ALLOW_CONTEXT_REPLAY ", 0x00400000)  // deprecated - don't use this flag!!!
    registerFlag("ASC_RET_FRAGMENT_ONLY        ", 0x00800000)
    registerFlag("ASC_RET_NO_TOKEN             ", 0x01000000)
    registerFlag("ASC_RET_NO_ADDITIONAL_TOKEN  ", 0x02000000)  // *INTERNAL*    )
    return flagText[flag]
  }

  fun printCtxMsg(name: String, rv: Int, tokenSize: Int, ctxAttrRef: IntByReference) {
    var flags = ctxAttrRef.value
    println("$name " + "%x".format(rv) + " "
      + when (rv) {
      WinError.SEC_I_CONTINUE_NEEDED -> "continue"
      0 -> "ok"
      else -> Kernel32Util.formatMessage(rv)
      }
      + ", tokenSize: $tokenSize, flags: $flags "
      + sspiFlagsToString(flags, if (name.equals("client")) "isc" else "asc"))
  }

  /**
   * @param flagsType: isc for InitializeSecurityContext or asc for AcceptSecurityContext flags
   */
  fun sspiFlagsToString(flags: Int, flagsType: String): String {
    var bit = 1
    val flagiStr = mutableListOf<String>()

    var remainingFlags = flags
    while (remainingFlags > 0) {
      if (remainingFlags.and(1) != 0)
        if (flagsType.equals("isc"))
          flagiStr.add(getIscFlagText(bit)!!)
        else
          flagiStr.add(getAscFlagText(bit)!!)
      bit *= 2
      remainingFlags = remainingFlags.shr(1)
    }
    return flagiStr.joinToString(", ")
  }

}

data class AcceptBytesResponse(
  val tokenBytes: ByteArray,
  val identity: String?,
  val shouldContinue: Boolean,
  val contextFlags: String
) {}

class ServerContext(serverName: String) {
  val hCred = Sspi.CredHandle()
  var ctx:Sspi.CtxtHandle? = null

  init {
    val rv = Secur32.INSTANCE.AcquireCredentialsHandle(serverName, "Negotiate", Sspi.SECPKG_CRED_INBOUND,
      null, null, null, null, hCred, Sspi.TimeStamp())
    require(rv == 0)
  }

  fun acceptBytes(inputTokenBytes: ByteArray): AcceptBytesResponse {
    val newServerCtx = Sspi.CtxtHandle()
    val serverInputToken = if (inputTokenBytes == null)
      Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE)
    else
      Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, inputTokenBytes)
    val outputServerToken = Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE)
    val ctxAttrRef = IntByReference()
    var rv = Secur32.INSTANCE.AcceptSecurityContext(hCred, ctx, serverInputToken, Sspi.ISC_REQ_CONNECTION,
      Sspi.SECURITY_NATIVE_DREP,
      ///* Sspi.SECURITY_NETWORK_DREP */ 0,
      newServerCtx, outputServerToken, ctxAttrRef, Sspi.TimeStamp())
    val tokenSize = outputServerToken.pBuffers[0].cbBuffer
    val returnTokenBytes = outputServerToken.bytes
    IwaJnaAuth.printCtxMsg("server", rv, tokenSize, ctxAttrRef)
    var identity: String? = null
    if (rv == 0) {
      val phContextToken = WinNT.HANDLEByReference();
      val rv2 = Secur32.INSTANCE.QuerySecurityContextToken(newServerCtx, phContextToken);
      if (rv2 != 0)
        println("%x".format(rv2) + " " + Kernel32Util.formatMessage(rv2))
      else {
        val account = Advapi32Util.getTokenAccount(phContextToken.value)
        identity = account.fqn
      }
    }
    ctx = if (rv == 0) null else newServerCtx
    return AcceptBytesResponse(
      returnTokenBytes,
      identity,
      rv == WinError.SEC_I_CONTINUE_NEEDED,
      IwaJnaAuth.sspiFlagsToString(ctxAttrRef.value, "asc")
    )
  }
}
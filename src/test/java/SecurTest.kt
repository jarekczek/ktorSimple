import com.sun.jna.platform.win32.*
import com.sun.jna.ptr.IntByReference
import org.junit.Test

class SecurTest {
  @Test
  fun test1() {
    val pkgCount = IntByReference()
    val pkgInfo = Sspi.PSecPkgInfo()
    var rv = Secur32.INSTANCE.EnumerateSecurityPackages(pkgCount, pkgInfo)
    require(rv == 0)
    for(pkgStruct in pkgInfo.pPkgInfo.toArray(pkgCount.value)) {
      val pkg = pkgStruct as Sspi.SecPkgInfo
      println(pkg.Name)
      testPackage(pkg.Name, "HTTP/LENOVO8G")
      println()
      break
    }
  }

  fun testPackage(name: String, targetName: String) {
    val hCred = Sspi.CredHandle()
    var rv = Secur32.INSTANCE.AcquireCredentialsHandle("toja", name, Sspi.SECPKG_CRED_OUTBOUND,
      null, null, null, null, hCred, Sspi.TimeStamp())
    require(rv == 0)

    val hServerCred = Sspi.CredHandle()
    rv = Secur32.INSTANCE.AcquireCredentialsHandle("tojaserwer", name, Sspi.SECPKG_CRED_INBOUND,
      null, null, null, null, hServerCred, Sspi.TimeStamp())
    require(rv == 0)

    var clientCtx:Sspi.CtxtHandle? = null
    var serverCtx:Sspi.CtxtHandle? = null
    val ctxAttrRef = IntByReference()
    var tokenBytes: ByteArray? = null
    var tokenSize = 0

    while (true) {
      val newClientCtx = Sspi.CtxtHandle()
      val inputClientToken = if (tokenBytes == null)
        Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE)
      else
        Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, tokenBytes)
      val outputClientToken = Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE)
      rv = Secur32.INSTANCE.InitializeSecurityContext(hCred, clientCtx, targetName, Sspi.ISC_REQ_CONNECTION, 0,
        0 /* Sspi.SECURITY_NETWORK_DREP */,
        //Sspi.SECURITY_NATIVE_DREP,
        inputClientToken, 0, newClientCtx, outputClientToken, ctxAttrRef, Sspi.TimeStamp())
      tokenSize = outputClientToken.pBuffers[0].cbBuffer
      clientCtx = if (rv == 0) null else newClientCtx
      tokenBytes = outputClientToken.bytes
      printCtxMsg("client", rv, tokenSize, ctxAttrRef)
      if (rv == 0 && tokenSize == 0)
        break;
      require(rv == 0 || rv == WinError.SEC_I_CONTINUE_NEEDED)
      println()

      val newServerCtx = Sspi.CtxtHandle()
      val serverInputToken = Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, tokenBytes)
      val outputServerToken = Sspi.SecBufferDesc(Sspi.SECBUFFER_TOKEN, Sspi.MAX_TOKEN_SIZE)
      rv = Secur32.INSTANCE.AcceptSecurityContext(hServerCred, serverCtx, serverInputToken, Sspi.ISC_REQ_CONNECTION,
        Sspi.SECURITY_NATIVE_DREP,
        ///* Sspi.SECURITY_NETWORK_DREP */ 0,
        newServerCtx, outputServerToken, ctxAttrRef, Sspi.TimeStamp())
      tokenSize = outputServerToken.pBuffers[0].cbBuffer
      tokenBytes = outputServerToken.bytes
      printCtxMsg("server", rv, tokenSize, ctxAttrRef)
      if (rv == 0) {
        val phContextToken = WinNT.HANDLEByReference();
        val rv2 = Secur32.INSTANCE.QuerySecurityContextToken(newServerCtx, phContextToken);
        if (rv2 != 0)
          println("%x".format(rv2) + " " + Kernel32Util.formatMessage(rv2))
        else {
          val account = Advapi32Util.getTokenAccount(phContextToken.value)
          println("fqn: " + account.fqn)
        }
      }
      serverCtx = if (rv == 0) null else newServerCtx
      if (rv == 0 && tokenSize == 0)
          break
      require(rv == 0 || rv == WinError.SEC_I_CONTINUE_NEEDED)
      println()
    }
    Secur32.INSTANCE.DeleteSecurityContext(clientCtx)
    Secur32.INSTANCE.DeleteSecurityContext(serverCtx)
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

  private fun printCtxMsg(name: String, rv: Int, tokenSize: Int, ctxAttrRef: IntByReference) {
    var flags = ctxAttrRef.value
    println("$name " + "%x".format(rv) + " " + when (rv) {
      WinError.SEC_I_CONTINUE_NEEDED -> "continue"
      0 -> "ok"
      else -> Kernel32Util.formatMessage(rv)
    } + ", tokenSize: $tokenSize, flags: $flags")
    var bit = 1
    while (flags > 0) {
      if (flags.and(1) != 0)
        if (name.equals("client"))
          println(getIscFlagText(bit))
        else
          println(getAscFlagText(bit))
      bit *= 2
      flags = flags.shr(1)
    }
  }
}
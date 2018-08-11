import auth.IwaJnaAuth
import com.sun.jna.platform.win32.*
import com.sun.jna.ptr.IntByReference
import io.ktor.util.encodeBase64
import org.junit.Test

class SecurTest {
  //@Test
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
      IwaJnaAuth.printCtxMsg("client", rv, tokenSize, ctxAttrRef)
      println(encodeBase64(tokenBytes))
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
      IwaJnaAuth.printCtxMsg("server", rv, tokenSize, ctxAttrRef)
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

}
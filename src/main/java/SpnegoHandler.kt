import com.sun.jna.platform.win32.Win32Exception
import com.sun.jna.platform.win32.WinError
import io.ktor.util.decodeBase64
import waffle.windows.auth.IWindowsSecurityContext
import waffle.windows.auth.impl.WindowsAuthProviderImpl
import waffle.windows.auth.impl.WindowsSecurityContextImpl

object SpnegoHandler {
  val provider = WindowsAuthProviderImpl()
  fun getAnswer(clientToken: ByteArray): Pair<String?, ByteArray?> {
    //println("incoming token: " + String(clientToken))
    try {
      val serverCtx = provider.acceptSecurityToken("connId", clientToken, "Negotiate")
      val backToken = serverCtx.token
      //println("back token: " + if (backToken == null) "null" else String(backToken))
      val identity = if (serverCtx.isContinue) null else serverCtx.identity.fqn
      if (!serverCtx.isContinue) {
        //println("authenticated as " + identity)
        provider.resetSecurityToken("connId")
      }
      return Pair(identity, backToken)
    } catch(e: Win32Exception) {
      if (e.errorCode == WinError.SEC_E_LOGON_DENIED)
        println("logon denied")
      else
        println("Windows exception %x".format(e.errorCode))
      return Pair(null, null)
    }
  }
}
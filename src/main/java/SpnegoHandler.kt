import io.ktor.util.decodeBase64
import waffle.windows.auth.IWindowsSecurityContext
import waffle.windows.auth.impl.WindowsAuthProviderImpl
import waffle.windows.auth.impl.WindowsSecurityContextImpl

object SpnegoHandler {
  val provider = WindowsAuthProviderImpl()
  fun getAnswer(clientToken: ByteArray): Pair<String?, ByteArray?> {
    //println("incoming token: " + String(clientToken))
    val serverCtx = provider.acceptSecurityToken("connId", clientToken, "Negotiate")
    val backToken = serverCtx.token
    //println("back token: " + if (backToken == null) "null" else String(backToken))
    val identity = if (serverCtx.isContinue) null else serverCtx.identity.fqn
    if (!serverCtx.isContinue) {
      //println("authenticated as " + identity)
      provider.resetSecurityToken("connId")
    }
    return Pair(identity, backToken)
  }
}
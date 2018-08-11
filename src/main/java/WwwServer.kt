import auth.IwaJnaAuth
import auth.interceptAndAuthenticateIWA
import htmlbuilder.htmlBuilderRoutes
import io.ktor.application.Application
import io.ktor.application.ApplicationCall
import io.ktor.application.ApplicationCallPipeline
import io.ktor.application.call
import io.ktor.html.respondHtml
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.pipeline.PipelinePhase
import io.ktor.response.ApplicationResponse
import io.ktor.response.respond
import io.ktor.response.respondText
import io.ktor.response.respondWrite
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import io.ktor.util.decodeBase64
import io.ktor.util.encodeBase64
import kotlinx.html.body
import kotlinx.html.head
import kotlinx.html.title
import org.ietf.jgss.GSSCredential
import org.ietf.jgss.GSSManager
import org.ietf.jgss.GSSName
import org.ietf.jgss.Oid
import sun.security.jgss.GSSHeader
import waffle.windows.auth.impl.WindowsAuthProviderImpl
import waffle.windows.auth.impl.WindowsSecurityContextImpl
import java.security.KeyStore
import javax.security.auth.login.LoginContext

fun main(args: Array<String>) {
  class DummyClass {}

  val module: Application.() -> Unit = {
    intercept(ApplicationCallPipeline.Call) {
      context.request.headers["Authorization"]?.let { println("authorization header: $it") }
    }

    interceptAndAuthenticateIWA()

    routing {
      get("/") {
        val sb = StringBuilder()
        sb.appendln("<h1>Hello, module world 8081!</h1>")
        sb.appendln("<br/>")
        sb.appendln("<a href='/menu'>menu</a>")
        call.respondText(sb.toString(), ContentType.Text.Html)
      }
      get("/p1") {
        call.respondText("This is page 1.")
      }
      htmlBuilderRoutes()
      get("/spnego") {
        //https://tuhrig.de/a-windows-sso-for-java-on-client-and-server/
        var identity: String? = null
        val authNegHeader = context.request.headers["Authorization"]?.replace("Negotiate ", "")
        //println("authNegHeader: $authNegHeader")
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
          val negResult = SpnegoHandler.getAnswer(authNegHeaderBytes)
          val backToken = negResult.second
          identity = negResult.first
          backToken?.let { context.response.headers.append("WWW-Authenticate", "Negotiate " + encodeBase64(backToken)) }
          if (identity == null) {
            if (backToken != null)
              println("requiring to continue authentication")
            else
              println("authentication failed")
          }
          else
            println("successfully authenticated $identity")
        }
        context.response.status(if (identity == null) HttpStatusCode.Unauthorized else HttpStatusCode.OK)
        call.respondWrite(ContentType.Text.Plain) {
          if (identity != null)
            write("Witaj " + identity)
        }
      }
      get("/ssl") {
        call.respondText("ssl")
      }
    }
  }

val keyStore = KeyStore.getInstance("JKS")
keyStore.load(DummyClass::class.java.getResourceAsStream("WwwServerKt.jks"), "changeit".toCharArray())
println("keystore: " + keyStore)
println("keystore aliases: " + keyStore.aliases().toList().joinToString(","))

val env = applicationEngineEnvironment {
  connector {
    port = 8080
  }
  try {
    val herokuPort = Integer.parseInt(System.getenv("PORT"))
    println("heroku port: $herokuPort")
    connector {
      port = herokuPort
    }
  } catch(e: Exception) {
    println("no heroku port given in PORT env")
  }
  sslConnector(
    keyStore,
    "localhost",
    { "changeit".toCharArray() },
    { "changeit".toCharArray() },
    {
      port = 8081
    }
  )
  modules.add(module)
}

val server = embeddedServer(Netty, env)
println("starting server")
server.start(wait = false)
println("server started")
try {
  Runtime.getRuntime().exec("c:\\program_files\\espeak\\command_line\\espeak.exe -s 300 server")
} catch (e: Exception) {}
Thread.sleep(10*1000)
//println("stoping server")
//server.stop(1, 1, TimeUnit.SECONDS)
//println("server stoped")
}


import auth.interceptAndAuthenticateIWA
import com.auth0.jwt.JWT
import htmlbuilder.htmlBuilderRoutes
import io.ktor.application.Application
import io.ktor.application.ApplicationCallPipeline
import io.ktor.application.call
import io.ktor.application.install
import io.ktor.auth.Authentication
import io.ktor.auth.AuthenticationFailedCause
import io.ktor.auth.OAuthAccessTokenResponse
import io.ktor.auth.OAuthServerSettings
import io.ktor.auth.authenticate
import io.ktor.auth.authentication
import io.ktor.auth.jwt.JWTPrincipal
import io.ktor.auth.oauth
import io.ktor.client.HttpClient
import io.ktor.client.engine.apache.Apache
import io.ktor.html.each
import io.ktor.http.ContentType
import io.ktor.http.HttpMethod
import io.ktor.http.HttpStatusCode
import io.ktor.response.respondRedirect
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
import java.security.KeyStore

fun main(args: Array<String>) {
  class DummyClass {}

  val module: Application.() -> Unit = {
    intercept(ApplicationCallPipeline.Call) {
      context.request.headers["Authorization"]?.let { println("authorization header: $it") }
    }

    interceptAndAuthenticateIWA()

    install(Authentication) {
      oauth {
        client = HttpClient(Apache)
        providerLookup = {
          OAuthServerSettings.OAuth2ServerSettings(
            name = "ooo1",
            authorizeUrl = "http://localhost:8080/auth/realms/r1/protocol/openid-connect/auth",
            accessTokenUrl = "http://localhost:8080/auth/realms/r1/protocol/openid-connect/token",
            clientId = "ktorSimple",
            clientSecret = "ppppsdfas",
            requestMethod = HttpMethod.Post
          )
        }
        urlProvider = { "http://localhost:8089/o2/success" }
      }
    }

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

      authenticate() {
        handle {
          println("principal: " + call.authentication.principal<OAuthAccessTokenResponse>())
        }
        get("/o2") {
          call.respondText("oauth2 ok")
        }
        get("/o2/success") {
          val sb = StringBuilder()
          call.authentication.errors.forEach {
            val err = it.value
            sb.appendln("error: " + it.key + ", " + if (err is AuthenticationFailedCause.Error) "" + err.cause else "" + err)
          }
          val principal = call.authentication.principal<OAuthAccessTokenResponse.OAuth2>()
          sb.appendln("o2success " + principal)
          if (principal != null) {
            principal?.extraParameters?.forEach { s, list ->
              sb.appendln("principal: " + s + ", " + list.joinToString(", "))
            }
            val jwt = JWT.decode(principal?.accessToken)
            jwt?.claims?.forEach { t, u -> sb.appendln("claim $t: ${u.asString()}") }
            sb.appendln(jwt.header)
          }
          call.respondText(sb.toString())
        }
      }
      get("/o2/authorize") {
        //call.respondText("authorize to " + call.parameters.getAll("redirect_uri"))
        call.respondRedirect(call.parameters.get("redirect_uri")!!)
      }
      get("/o2/token") {
        call.respondText("token")
      }
    }
  }

val keyStore = KeyStore.getInstance("JKS")
keyStore.load(DummyClass::class.java.getResourceAsStream("WwwServerKt.jks"), "changeit".toCharArray())
println("keystore: " + keyStore)
println("keystore aliases: " + keyStore.aliases().toList().joinToString(","))

val env = applicationEngineEnvironment {
  connector {
    port = 8089
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
  modules.add(Application::eventsModule)
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


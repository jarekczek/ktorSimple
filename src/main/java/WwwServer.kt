import io.ktor.application.Application
import io.ktor.application.call
import io.ktor.http.ContentType
import io.ktor.response.respondText
import io.ktor.routing.get
import io.ktor.routing.routing
import io.ktor.server.engine.applicationEngineEnvironment
import io.ktor.server.engine.connector
import io.ktor.server.engine.embeddedServer
import io.ktor.server.engine.sslConnector
import io.ktor.server.netty.Netty
import java.security.KeyStore

fun main(args: Array<String>) {
  println("hello")

  class DummyClass {}

  val module: Application.() -> Unit = {
    routing {
      get("/") {
        call.respondText("Hello, module world 8081!", ContentType.Text.Html)
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
  Thread.sleep(10*1000)
  //println("stoping server")
  //server.stop(1, 1, TimeUnit.SECONDS)
  //println("server stoped")
}

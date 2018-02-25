import java.util.concurrent.TimeUnit
import io.ktor.application.*
import io.ktor.http.*
import io.ktor.response.*
import io.ktor.routing.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*

fun main(args: Array<String>) {
  println("hello")
  val server = embeddedServer(Netty, 8080) {
    routing {
      get("/") {
        call.respondText("Hello, world 8080!", ContentType.Text.Html)
      }
    }
  }
  println("starting server")
  server.start(wait = false)
  println("server started")
  Thread.sleep(10*1000)
  println("stoping server")
  server.stop(1, 1, TimeUnit.SECONDS)
  println("server stoped")
}

import io.ktor.client.HttpClient
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.cio.CIO
import io.ktor.client.engine.config
import io.ktor.client.request.get
import kotlinx.coroutines.experimental.async
import kotlinx.coroutines.experimental.runBlocking
import org.junit.Test

class CliTest {

  @Test
  fun test1() {
    runBlocking {
      println("inside async")
      val cli = HttpClient(CIO)
      println("client ready")
      println(cli.get<String>("http://localhost:8089"))
      println("after get")
    }
  }
}
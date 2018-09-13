import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.engine.HttpClientEngine
import io.ktor.client.engine.cio.CIO
import io.ktor.client.engine.config
import io.ktor.client.request.get
import kotlinx.coroutines.experimental.async
import kotlinx.coroutines.experimental.runBlocking
import org.junit.Test
import java.io.IOException
import java.net.ConnectException
import java.security.SecureRandom

class CliRemoteTest {

  @Test
  fun test1() {
    val url = "http://192.168.16.110/"
    //val url = "http://192.168.16.110:8089/events"
    //"https://eventserver75.herokuapp.com/events/read?code=weather&last"
    runBlocking {
      println("inside async")
      val cli = HttpClient(CIO.config {
        this.endpoint.keepAliveTime = 1
        https.randomAlgorithm = "SHA1PRNG"
      })
      println("client ready")
      // Warming up the connection.
      try {
        cli.get<String>("http://192.168.16.110:9999")
      } catch (e: IOException) {}
      IntRange(0, 2).forEach {
        val t = System.currentTimeMillis()
        try {
          println(cli.get<String>(url).lines().firstOrNull())
        } catch (e: IOException) {
          println(e.message)
        }
        println("after get " + (System.currentTimeMillis() - t));
        Thread.sleep(1500)
      }
    }
  }

  @Test
  fun test2() {
    test1()
  }
}
package htmlbuilder

import io.ktor.html.Placeholder
import io.ktor.html.Template
import io.ktor.html.insert
import kotlinx.html.*

class PageTemplate : Template<HTML> {
  val content = Placeholder<FlowContent>()
  override fun HTML.apply() {
    head {
      title("Ktor sample pages")
    }
    body {
      div {
        ul {
          autoLiLink("/", "Home")
          autoLiLink("/html/template", "Templates")
        }
      }
      hr()
      insert(content)
    }
  }
}

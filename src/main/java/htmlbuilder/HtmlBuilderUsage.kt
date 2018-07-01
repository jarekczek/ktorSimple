package htmlbuilder

import io.ktor.application.ApplicationCall
import io.ktor.application.call
import io.ktor.html.respondHtml
import io.ktor.html.respondHtmlTemplate
import io.ktor.http.HttpMethod
import io.ktor.pipeline.PipelineInterceptor
import io.ktor.response.respondText
import io.ktor.routing.Route
import io.ktor.routing.get
import io.ktor.routing.route
import kotlinx.html.*

fun Route.htmlBuilderRoutes(): Unit {
  get("/menu") {
    call.respondHtml {
      body {
        h1 { text("Menu") }
        ul {
          autoLiLink("/html/simple")
          autoLiLink("/html/template")
        }
      }
    }
  }
  get("/html/simple") {
    call.respondHtml {
      body {
        text("This is straight html builder usage, with no templates.")
      }
    }
  }
  get("html/page1") {
    call.respondHtmlTemplate(PageTemplate()) {
      content {
        p {
          text("This is page1 content. Go to ")
          autoLink("page2")
        }
      }
    }
  }
  get("html/page2") {
    call.respondHtmlTemplate(PageTemplate()) {
      content {
        p { text("This is page2 content.")}
      }
    }
  }
  get("html/template") {
    call.respondHtmlTemplate(PageTemplate()) {
      content {
        ol {
          autoLiLink("page1")
          autoLiLink("page2")
        }
      }
    }
  }

}

fun OL.autoLiLink(href: String, label: String? = null) {
  li {
    a(href) { text (label ?: href) }
  }
}

fun UL.autoLiLink(href: String, label: String? = null) {
  li {
    a(href) { text (label ?: href) }
  }
}

fun FlowContent.autoLink(href: String) {
  a(href) { text(href) }
}
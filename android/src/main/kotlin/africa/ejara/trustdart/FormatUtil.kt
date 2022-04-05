package africa.ejara.trustdart

object FormatUtil {

  fun cut(text: String, cutLength: Int): String {
    if (cutLength == 0 || text.length <= cutLength) {
      return text
    }
    return text.substring(0, cutLength) + "..."
  }

  fun pad(s: String, length: Int): String {
    val sb = StringBuilder()
    sb.append("-->")
    for (i in 0 until length - s.length) {
      sb.append("\u0020")
    }
    sb.append(s)
    return String(sb)
  }

  fun pad30(s: String): String {
    val sb = StringBuilder()
    sb.append("-->")
    for (i in 0 until 30 - s.length) {
      sb.append("\u0020")
    }
    sb.append(s)
    return String(sb)
  }

}
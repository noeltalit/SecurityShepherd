package utils;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Locale;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Anti-CSRF helpers for state changing endpoints. <br>
 * <br>
 * Provides per-session, unpredictable synchronizer tokens validated with a constant-time comparison
 * and a strict same-origin check based on the Origin / Referer headers. <br>
 * <br>
 * This file is part of the Security Shepherd Project.
 *
 * <p>The Security Shepherd project is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software Foundation, either
 * version 3 of the License, or (at your option) any later version.<br>
 *
 * <p>The Security Shepherd project is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
 * PURPOSE. See the GNU General Public License for more details.<br>
 *
 * <p>You should have received a copy of the GNU General Public License along with the Security
 * Shepherd project. If not, see <http://www.gnu.org/licenses/>.
 */
public final class CsrfGuard {

  private static final Logger log = LogManager.getLogger(CsrfGuard.class);

  private CsrfGuard() {}

  /**
   * Returns the anti-CSRF token stored in the session under the given attribute, creating a new
   * cryptographically random one if none exists yet.
   *
   * @param ses The user's session
   * @param attributeName Session attribute holding the token
   * @return The session bound token
   */
  public static String getOrCreateToken(HttpSession ses, String attributeName) {
    Object existing = ses.getAttribute(attributeName);
    if (existing != null && !existing.toString().isEmpty()) {
      return existing.toString();
    }
    String token = Hash.randomString();
    ses.setAttribute(attributeName, token);
    return token;
  }

  /**
   * Validates a submitted token against the token bound to the session, using a constant-time
   * comparison. Missing or empty values are never valid.
   *
   * @param ses The user's session
   * @param attributeName Session attribute holding the expected token
   * @param submitted Token submitted with the request
   * @return True only if the submitted token matches the session token
   */
  public static boolean isValidToken(HttpSession ses, String attributeName, String submitted) {
    if (ses == null || submitted == null) {
      return false;
    }
    Object expected = ses.getAttribute(attributeName);
    if (expected == null) {
      return false;
    }
    return constantTimeEquals(expected.toString(), submitted.trim());
  }

  /**
   * Constant-time string comparison. Empty or null values never match.
   *
   * @param expected Expected value
   * @param submitted Submitted value
   * @return True if both values are non-empty and equal
   */
  public static boolean constantTimeEquals(String expected, String submitted) {
    if (expected == null || submitted == null || expected.isEmpty() || submitted.isEmpty()) {
      return false;
    }
    return MessageDigest.isEqual(
        expected.getBytes(StandardCharsets.UTF_8), submitted.getBytes(StandardCharsets.UTF_8));
  }

  /**
   * Strict same-origin check for state changing requests. The request must carry an Origin header
   * (or, failing that, a Referer header) whose host and port match the Host the request was sent
   * to. Requests without either header, or with an opaque "null" origin, are rejected.
   *
   * @param request The incoming request
   * @return True if the request provably originates from this application
   */
  public static boolean isSameOrigin(HttpServletRequest request) {
    String host = request.getHeader("Host");
    if (host == null || host.trim().isEmpty()) {
      return false;
    }
    String source = request.getHeader("Origin");
    if (source == null || source.trim().isEmpty()) {
      source = request.getHeader("Referer");
    }
    if (source == null || source.trim().isEmpty() || "null".equalsIgnoreCase(source.trim())) {
      log.debug("No usable Origin/Referer header on state changing request");
      return false;
    }
    try {
      URI uri = new URI(source.trim());
      if (uri.getHost() == null || uri.getScheme() == null) {
        return false;
      }
      String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
      int port = uri.getPort();
      String sourceAuthority = uri.getHost().toLowerCase(Locale.ROOT);
      if (port != -1
          && !(("http".equals(scheme) && port == 80) || ("https".equals(scheme) && port == 443))) {
        sourceAuthority += ":" + port;
      }
      String target = host.trim().toLowerCase(Locale.ROOT);
      if (target.endsWith(":80") && "http".equals(scheme)) {
        target = target.substring(0, target.length() - 3);
      } else if (target.endsWith(":443") && "https".equals(scheme)) {
        target = target.substring(0, target.length() - 4);
      }
      boolean same = sourceAuthority.equals(target);
      if (!same) {
        log.debug("Cross origin request blocked: " + sourceAuthority + " != " + target);
      }
      return same;
    } catch (Exception e) {
      log.debug("Unparsable Origin/Referer header: " + e.toString());
      return false;
    }
  }

  /**
   * Checks that the request body is declared as JSON (application/json, optional parameters).
   * Rejects the text/plain, form and multipart types that a cross-site HTML form can send without a
   * CORS preflight.
   *
   * @param request The incoming request
   * @return True if the Content-Type is application/json
   */
  public static boolean isJsonContentType(HttpServletRequest request) {
    String contentType = request.getContentType();
    if (contentType == null) {
      return false;
    }
    String mediaType = contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
    return "application/json".equals(mediaType);
  }
}

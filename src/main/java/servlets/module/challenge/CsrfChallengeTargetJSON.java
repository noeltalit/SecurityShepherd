package servlets.module.challenge;

import dbProcs.Getter;
import dbProcs.Setter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Scanner;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import utils.CsrfGuard;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Cross Site Request Forgery Challenge Target SON - Does not return Result key <br>
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
 *
 * @author Mark Denihan
 */
public class CsrfChallengeTargetJSON extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(CsrfChallengeTargetJSON.class);
  private static final String CSRF_TOKEN_ATTRIBUTE = "csrfChallengeJsonTargetToken";
  private static String levelName = "CSRF JSON Target";

  /** State changing requests must use POST. Other methods are refused without side effects. */
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug(levelName + " refused non POST request");
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle csrfGenerics =
        ResourceBundle.getBundle("i18n.servlets.challenges.csrf.csrfGenerics", locale);
    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());
    out.write(csrfGenerics.getString("target.incrementFailed"));
  }

  /**
   * Increments another user's CSRF counter. Expects JSON formed data and is protected against CSRF:
   * application/json Content-Type, same-origin and a per-session anti-CSRF token are required.
   *
   * @param userId User identifier to be incremented
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug(levelName + " Servlet");

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle csrfGenerics =
        ResourceBundle.getBundle("i18n.servlets.challenges.csrf.csrfGenerics", locale);

    response.setContentType("text/html");
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());
    try {
      boolean result = false;
      HttpSession ses = request.getSession(true);
      if (Validate.validateSession(ses)) {
        ShepherdLogManager.setRequestIp(
            request.getRemoteAddr(),
            request.getHeader("X-Forwarded-For"),
            ses.getAttribute("userName").toString());
        log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());

        String userId = (String) ses.getAttribute("userStamp");
        CsrfGuard.getOrCreateToken(ses, CSRF_TOKEN_ATTRIBUTE);
        // Anti-CSRF: a cross-site HTML form can only send text/plain, urlencoded or multipart
        // bodies, so a strict application/json Content-Type is required, together with a
        // same-origin request and the per-session token (header or JSON field)
        boolean csrfValid = CsrfGuard.isJsonContentType(request) && CsrfGuard.isSameOrigin(request);
        String plusId = null;
        if (csrfValid) {
          log.debug("Getting JSON String");
          String jsonData = extractPostRequestBody(request);
          log.debug("POST body: " + jsonData);
          JSONObject json = new JSONObject(jsonData);
          log.debug("Getting userId");
          plusId = json.optString("userId", null);
          log.debug("User Submitted - " + plusId);
          String submittedToken = request.getHeader("X-CSRF-Token");
          if (submittedToken == null) {
            submittedToken = json.optString("csrfToken", null);
          }
          csrfValid = CsrfGuard.isValidToken(ses, CSRF_TOKEN_ATTRIBUTE, submittedToken);
        }
        if (!csrfValid) {
          log.debug(levelName + " request refused: bad Content-Type, origin or anti-CSRF token");
        }
        if (csrfValid && plusId != null && !userId.equals(plusId)) {
          String ApplicationRoot = getServletContext().getRealPath("");
          String userName = (String) ses.getAttribute("userName");
          String attackerName = Getter.getUserName(ApplicationRoot, plusId);
          if (attackerName != null) {
            log.debug(userName + " is been CSRF'd by " + attackerName);

            log.debug("Attempting to Increment ");
            String moduleHash = CsrfChallengeJSON.getLevelHash();
            String moduleId = Getter.getModuleIdFromHash(ApplicationRoot, moduleHash);
            result = Setter.updateCsrfCounter(ApplicationRoot, moduleId, plusId);
          } else {
            log.error("UserId '" + plusId + "' could not be found.");
          }
        }

        if (result) {
          out.write(csrfGenerics.getString("target.incrementSuccess"));
        } else {
          out.write(csrfGenerics.getString("target.incrementFailed"));
        }
      } else {
        out.write(csrfGenerics.getString("target.noSession"));
      }
    } catch (Exception e) {
      out.write(errors.getString("error.funky"));
      log.fatal(levelName + " - " + e.toString());
    }
  }

  @SuppressWarnings("resource")
  static String extractPostRequestBody(HttpServletRequest request) throws IOException {
    if ("POST".equalsIgnoreCase(request.getMethod())) {
      Scanner s = new Scanner(request.getInputStream(), "UTF-8").useDelimiter("\\A");
      return s.hasNext() ? s.next() : "";
    }
    return "";
  }
}

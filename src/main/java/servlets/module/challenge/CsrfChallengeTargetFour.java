package servlets.module.challenge;

import dbProcs.Database;
import dbProcs.Getter;
import dbProcs.Setter;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.CsrfGuard;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Cross Site Request Forgery Challenge Target Four - Does not return Result key <br>
 * <br>
 * Weak Nonce Variety can be broken <br>
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
public class CsrfChallengeTargetFour extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static String moduleHash =
      "84118752e6cd78fecc3563ba2873d944aacb7b72f28693a23f9949ac310648b5";
  private static final Logger log = LogManager.getLogger(CsrfChallengeTargetFour.class);
  private static String levelName = "CSRF Target 4";

  /** State changing requests must use POST. Other methods are refused without side effects. */
  public void doGet(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug(levelName + " refused non POST request");
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle csrfGenerics =
        ResourceBundle.getBundle("i18n.servlets.challenges.csrf.csrfGenerics", locale);
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());
    out.write(csrfGenerics.getString("target.incrementFailed"));
  }

  /**
   * CSRF vulnerable function that can be used by users to force other users to mark their CSRF
   * challenge Two as complete.
   *
   * @param userId User identifier to be incremented
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    log.debug(levelName + " Servlet");
    PrintWriter out = response.getWriter();
    out.print(getServletInfo());

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle csrfGenerics =
        ResourceBundle.getBundle("i18n.servlets.challenges.csrf.csrfGenerics", locale);

    String storedToken = new String();
    try {
      String ApplicationRoot = getServletContext().getRealPath("");
      String csrfTokenName = "csrfChallengeFourNonce";
      boolean result = false;
      HttpSession ses = request.getSession(true);
      String userId = (String) ses.getAttribute("userStamp");
      if (Validate.validateSession(ses)) {
        ShepherdLogManager.setRequestIp(
            request.getRemoteAddr(),
            request.getHeader("X-Forwarded-For"),
            ses.getAttribute("userName").toString());
        log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
        // Get CSRF Token From session
        // The token is issued (and shown to its owner only) by the challenge page. It is never
        // disclosed by this endpoint.
        if (ses.getAttribute(csrfTokenName) == null
            || ses.getAttribute(csrfTokenName).toString().isEmpty()) {
          log.debug("No CSRF Token found in session");
          storedToken = "";
        } else {
          storedToken = "" + ses.getAttribute(csrfTokenName);
        }
        log.debug("Victom is - " + userId);
        String plusId = String.valueOf(request.getParameter("userId")).trim();
        log.debug("User Submitted - " + plusId);
        String csrfToken =
            request.getParameter("csrfToken") == null
                ? ""
                : request.getParameter("csrfToken").trim();
        log.debug("csrfToken Submitted - '" + csrfToken + "'");
        log.debug("storedCsrf Token is - '" + storedToken + "'");

        if (!userId.equals(plusId)) {
          // The token must be the one bound to the victim's own session (and owned by the victim
          // in the DB), compared in constant time, and the request must be same-origin
          if (CsrfGuard.isSameOrigin(request)
              && CsrfGuard.constantTimeEquals(storedToken, csrfToken)
              && validCsrfToken(ApplicationRoot, userId, csrfToken)) {
            log.debug("'Valid' Nonce Value Submitted");
            String userName = (String) ses.getAttribute("userName");
            String attackerName = Getter.getUserName(ApplicationRoot, plusId);
            if (attackerName != null) {
              log.debug(userName + " is been CSRF'd by " + attackerName);

              log.debug("Attempting to Increment ");
              String moduleId = Getter.getModuleIdFromHash(ApplicationRoot, moduleHash);
              result = Setter.updateCsrfCounter(ApplicationRoot, moduleId, plusId);
            } else {
              log.error("UserId '" + plusId + "' could not be found in system.");
            }
          } else {
            log.debug("User " + plusId + " CSRF attack failed due to invalid nonce");
          }
        } else {
          log.debug("User " + userId + " is attacking themselves");
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

  /**
   * CSRF Validator that checks the submitted CSRF token belongs to the user submitting the request.
   *
   * @param ApplicationRoot Running context of the application
   * @param userId Identifier of the user submitting the request (owner of the session)
   * @param csrfToken CSRF Token value to search DB for
   * @return Returns true if the CSRF Token is Deemed valid
   */
  private static boolean validCsrfToken(String ApplicationRoot, String userId, String csrfToken) {
    log.debug("*** CSRF4.validCsrfToken ***");
    boolean result = false;
    Connection conn;

    try {
      conn = Database.getChallengeConnection(ApplicationRoot, "csrfChallengeFour");

      PreparedStatement prepstmt =
          conn.prepareStatement(
              "SELECT count(csrfTokenscol) FROM csrfTokens WHERE csrfTokenscol = ? AND userId = ?");
      prepstmt.setString(1, csrfToken);
      prepstmt.setString(2, userId);
      ResultSet rs = prepstmt.executeQuery();
      // count() always returns a row, so the count itself must be checked
      result = rs.next() && rs.getInt(1) > 0;
      Database.closeConnection(conn);

    } catch (SQLException e) {
      log.error("CSRF4 Token Check Failure: " + e.toString());
      result = false;
    }
    log.debug("*** END CSRF4.validCsrfToken ***");
    return result;
  }
}

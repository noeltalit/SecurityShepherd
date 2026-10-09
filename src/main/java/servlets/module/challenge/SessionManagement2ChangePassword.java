package servlets.module.challenge;

import dbProcs.Database;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.codec.binary.Hex;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Two - Password Reset Servlet Does not return result key <br>
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
public class SessionManagement2ChangePassword extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement2ChangePassword.class);
  private static String levelName = "Session Management Challenge Two (Change Pass)";
  public static String levelHash =
      "f5ddc0ed2d30e597ebacf5fdd117083674b19bb92ffc3499121b9e6a12c92959";

  /** How long a reset token stays valid for, in milliseconds */
  private static final long TOKEN_LIFE_MS = 15 * 60 * 1000;

  private static final int MIN_PASSWORD_LENGTH = 12;
  private static final int MAX_PASSWORD_LENGTH = 128;

  /** At most this many reset requests per address within the window */
  private static final int MAX_RESET_REQUESTS = 3;

  private static final long RESET_WINDOW_MS = 15 * 60 * 1000;

  private static final SessionManagement2.AttemptLimiter resetRequests =
      new SessionManagement2.AttemptLimiter(MAX_RESET_REQUESTS, RESET_WINDOW_MS);

  /** Invalid token submissions, so reset tokens cannot be guessed online */
  private static final SessionManagement2.AttemptLimiter tokenFailures =
      new SessionManagement2.AttemptLimiter(20, RESET_WINDOW_MS);

  private static final SecureRandom random = new SecureRandom();

  /**
   * Outstanding reset tokens, keyed by the SHA-256 of the token so the tokens themselves are never
   * stored. Each entry holds the user name and the expiry time.
   */
  private static final ConcurrentHashMap<String, String[]> resetTokens =
      new ConcurrentHashMap<String, String[]>();

  /**
   * Forgotten password function. A request for an email address creates a random, single use, short
   * lived reset token that would only be emailed to the owner of that address; the response never
   * contains a password or a token and is identical whether the address exists or not. Submitting a
   * valid token with a new password sets that password (as a salted Argon2id hash). Reset requests
   * are rate limited per address and invalid tokens are rate limited.
   *
   * @param subEmail Sub schema user email address
   * @param resetToken Reset token from the emailed link (second step only)
   * @param newPassword New password (second step only)
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle errors = ResourceBundle.getBundle("i18n.servlets.errors", locale);
    ResourceBundle bundle =
        ResourceBundle.getBundle(
            "i18n.servlets.challenges.sessionManagement.sessionManagement2", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());

      String htmlOutput = new String();
      log.debug(levelName + " Servlet accessed");
      try {
        log.debug("Getting Challenge Parameters");
        String subEmail = request.getParameter("subEmail");
        String resetToken = request.getParameter("resetToken");
        String newPassword = request.getParameter("newPassword");
        String applicationRoot = getServletContext().getRealPath("");

        if (resetToken != null && newPassword != null) {
          // Second step: the account owner follows the link that was emailed to them
          log.debug("Password reset token submitted");
          completeReset(applicationRoot, resetToken, newPassword);
          htmlOutput = bundle.getString("response.resetDone");
        } else {
          // First step: never change the password here and never put a password or token in the
          // response. The answer is the same whether or not the address belongs to an account.
          log.debug("Password reset requested");
          requestReset(applicationRoot, subEmail == null ? "" : subEmail);
          // Keep the usual "Changed To:" answer shape the challenge client expects, but in place
          // of a password it only says that the reset was sent to the address owner.
          htmlOutput =
              bundle.getString("response.changedTo") + " " + bundle.getString("response.resetSent");
        }
        log.debug("Outputting HTML");
        out.write(htmlOutput);
      } catch (Exception e) {
        out.write(errors.getString("error.funky"));
        log.fatal(levelName + " - " + e.toString());
      }
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }

  private void requestReset(String applicationRoot, String email) throws SQLException {
    String addressKey = "reset:" + email.trim().toLowerCase(Locale.ROOT);
    if (resetRequests.isBlocked(addressKey)) {
      log.debug("Too many reset requests for this address");
      return;
    }
    resetRequests.recordFailure(addressKey);
    Connection conn =
        Database.getChallengeConnection(applicationRoot, "BrokenAuthAndSessMangChalTwo");
    try {
      PreparedStatement callstmt =
          conn.prepareStatement("SELECT userName FROM users WHERE userAddress = ?");
      callstmt.setString(1, email);
      ResultSet resultSet = callstmt.executeQuery();
      if (resultSet.next()) {
        String userName = resultSet.getString(1);
        byte[] tokenBytes = new byte[32];
        random.nextBytes(tokenBytes);
        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
        // Only one outstanding token per account
        for (Map.Entry<String, String[]> entry : resetTokens.entrySet()) {
          if (entry.getValue()[0].equals(userName)) {
            resetTokens.remove(entry.getKey(), entry.getValue());
          }
        }
        resetTokens.put(
            sha256(token),
            new String[] {userName, Long.toString(System.currentTimeMillis() + TOKEN_LIFE_MS)});
        // The token is only ever delivered out of band, by email to the address on the account.
        // This challenge has no mail server, so it is not sent anywhere, and it is never logged or
        // returned in the HTTP response.
        log.debug("Reset token created");
      }
    } finally {
      Database.closeConnection(conn);
    }
  }

  private void completeReset(String applicationRoot, String token, String newPassword)
      throws SQLException {
    String tokenKey = "token";
    if (tokenFailures.isBlocked(tokenKey)) {
      log.debug("Too many invalid reset tokens");
      return;
    }
    // Removing the token makes it single use, whatever happens next
    String[] entry = resetTokens.remove(sha256(token));
    if (entry == null || System.currentTimeMillis() > Long.parseLong(entry[1])) {
      log.debug("Invalid or expired reset token");
      tokenFailures.recordFailure(tokenKey);
      return;
    }
    if (newPassword.length() < MIN_PASSWORD_LENGTH || newPassword.length() > MAX_PASSWORD_LENGTH) {
      log.debug("New password rejected by password policy");
      return;
    }
    Connection conn =
        Database.getChallengeConnection(applicationRoot, "BrokenAuthAndSessMangChalTwo");
    try {
      PreparedStatement callstmt =
          conn.prepareStatement("UPDATE users SET userPassword = ? WHERE userName = ?");
      callstmt.setString(1, SessionManagement2.hashPassword(newPassword));
      callstmt.setString(2, entry[0]);
      callstmt.execute();
      callstmt = conn.prepareStatement("COMMIT");
      callstmt.execute();
      SessionManagement2.attempts.reset("signIn:" + entry[0].toLowerCase(Locale.ROOT));
      log.debug("Password reset completed");
    } finally {
      Database.closeConnection(conn);
    }
  }

  private static String sha256(String value) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      return Hex.encodeHexString(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}

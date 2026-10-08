package servlets.module.challenge;

import dbProcs.Database;
import dbProcs.Getter;
import de.mkammerer.argon2.Argon2;
import de.mkammerer.argon2.Argon2Factory;
import de.mkammerer.argon2.Argon2Factory.Argon2Types;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Locale;
import java.util.Map;
import java.util.ResourceBundle;
import java.util.concurrent.ConcurrentHashMap;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;
import utils.Hash;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Session Management Challenge Two <br>
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
public class SessionManagement2 extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(SessionManagement2.class);
  private static String levelName = "Session Management Challenge Two";
  private static String levelHash =
      "d779e34a54172cbc245300d3bc22937090ebd3769466a501a5e7ac605b9f34b7";

  /** Argon2id cost settings used for this challenge's account passwords */
  private static final int ARGON2_ITERATIONS = 3;

  private static final int ARGON2_MEMORY_KB = 65536;
  private static final int ARGON2_PARALLELISM = 1;

  /** At most this many failed sign ins per user name within the window before it is blocked */
  private static final int MAX_SIGN_IN_FAILURES = 5;

  private static final long ATTEMPT_WINDOW_MS = 15 * 60 * 1000;

  /** Failed sign in counters, kept on the server */
  static final AttemptLimiter attempts =
      new AttemptLimiter(MAX_SIGN_IN_FAILURES, ATTEMPT_WINDOW_MS);

  /**
   * Hash of a random throwaway password, checked when the user name does not exist so that the
   * response takes as long as a real password check
   */
  private static final String DUMMY_HASH = hashPassword(Hash.randomString());

  private static Argon2 argon2() {
    return Argon2Factory.create(Argon2Types.ARGON2id);
  }

  /**
   * Hashes a password with a fresh random salt using Argon2id
   *
   * @param password The password to hash
   * @return The encoded Argon2id hash, including its salt and cost settings
   */
  static String hashPassword(String password) {
    char[] chars = password.toCharArray();
    Argon2 argon2 = argon2();
    try {
      return argon2.hash(ARGON2_ITERATIONS, ARGON2_MEMORY_KB, ARGON2_PARALLELISM, chars);
    } finally {
      argon2.wipeArray(chars);
    }
  }

  private static boolean verifyPassword(String encodedHash, String password) {
    char[] chars = password.toCharArray();
    Argon2 argon2 = argon2();
    try {
      return argon2.verify(encodedHash, chars);
    } catch (RuntimeException e) {
      log.error(levelName + " password check failed: " + e.toString());
      return false;
    } finally {
      argon2.wipeArray(chars);
    }
  }

  /**
   * Server side counter of attempts per key (a user name or an email address). Once a key reaches
   * the limit inside the window it is blocked until the window has passed. Nothing is slept;
   * blocked requests simply get the same generic answer without being processed.
   */
  static final class AttemptLimiter {
    private static final int MAX_TRACKED_KEYS = 10000;

    private final int maxAttempts;
    private final long windowMs;
    private final ConcurrentHashMap<String, long[]> counters =
        new ConcurrentHashMap<String, long[]>();

    AttemptLimiter(int maxAttempts, long windowMs) {
      this.maxAttempts = maxAttempts;
      this.windowMs = windowMs;
    }

    /**
     * @return true if the key has used up its attempts in the current window
     */
    boolean isBlocked(String key) {
      long[] counter = counters.get(key);
      if (counter == null) {
        return false;
      }
      synchronized (counter) {
        if (System.currentTimeMillis() - counter[1] > windowMs) {
          counters.remove(key, counter);
          return false;
        }
        return counter[0] >= maxAttempts;
      }
    }

    /** Counts one attempt against the key */
    void recordFailure(String key) {
      if (counters.size() > MAX_TRACKED_KEYS) {
        purgeExpired();
      }
      long now = System.currentTimeMillis();
      long[] counter = counters.putIfAbsent(key, new long[] {1, now});
      if (counter != null) {
        synchronized (counter) {
          if (now - counter[1] > windowMs) {
            counter[0] = 1;
            counter[1] = now;
          } else {
            counter[0]++;
          }
        }
      }
    }

    void reset(String key) {
      counters.remove(key);
    }

    private void purgeExpired() {
      long now = System.currentTimeMillis();
      for (Map.Entry<String, long[]> entry : counters.entrySet()) {
        long[] counter = entry.getValue();
        synchronized (counter) {
          if (now - counter[1] > windowMs) {
            counters.remove(entry.getKey(), counter);
          }
        }
      }
    }
  }

  /**
   * The user attempts to use this function to sign into a sub schema. Only a correct user name and
   * password, checked against a salted Argon2id hash, returns the result key. Every failure gets
   * the same generic message whether or not the user name exists, and repeated failures for a user
   * name are blocked for a while.
   *
   * @param subName Sub schema user name
   * @param subName Sub schema user password
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
        Object nameObj = request.getParameter("subName");
        Object passObj = request.getParameter("subPassword");
        String subName = new String();
        String subPass = new String();
        String userAddress = new String();
        if (nameObj != null) {
          subName = (String) nameObj;
        }
        if (passObj != null) {
          subPass = (String) passObj;
        }
        log.debug("subName = " + subName);

        log.debug("Getting ApplicationRoot");
        String ApplicationRoot = getServletContext().getRealPath("");
        log.debug("Servlet root = " + ApplicationRoot);

        Connection conn =
            Database.getChallengeConnection(ApplicationRoot, "BrokenAuthAndSessMangChalTwo");
        log.debug("Checking credentials");
        PreparedStatement callstmt;

        log.debug("Committing changes made to database");
        callstmt = conn.prepareStatement("COMMIT");
        callstmt.execute();
        log.debug("Changes committed.");

        // Throttle repeated failures per submitted user name, whether or not that account exists,
        // so the login form cannot be used to brute force a password or to tell accounts apart.
        String accountKey = "signIn:" + subName.trim().toLowerCase(Locale.ROOT);
        boolean authenticated = false;
        String signedInUser = null;
        if (attempts.isBlocked(accountKey)) {
          log.debug("Too many failed sign in attempts for this user name");
        } else {
          callstmt =
              conn.prepareStatement("SELECT userName, userPassword FROM users WHERE userName = ?");
          callstmt.setString(1, subName);
          log.debug("Executing authUser");
          ResultSet resultSet = callstmt.executeQuery();
          String storedHash = DUMMY_HASH;
          boolean userFound = false;
          if (resultSet.next()) {
            userFound = true;
            signedInUser = resultSet.getString(1);
            String dbHash = resultSet.getString(2);
            // Only salted Argon2id hashes are accepted. Anything else (seed placeholders, or the
            // unsalted SHA-1 hashes of passwords that the old reset function sent back to whoever
            // asked) can never sign in.
            if (dbHash != null && dbHash.startsWith("$argon2id$")) {
              storedHash = dbHash;
            } else {
              userFound = false;
            }
          }
          // Always run the same password check so the response time does not reveal whether the
          // user name exists
          boolean passwordOk = verifyPassword(storedHash, subPass);
          authenticated = userFound && passwordOk;
          if (authenticated) {
            attempts.reset(accountKey);
          } else {
            attempts.recordFailure(accountKey);
          }
        }
        if (authenticated) {
          log.debug("Successful Login");
          // Get key and add it to the output
          String userKey =
              Hash.generateUserSolution(
                  Getter.getModuleResultFromHash(ApplicationRoot, levelHash),
                  (String) ses.getAttribute("userName"));
          htmlOutput =
              "<h2 class='title'>"
                  + bundle.getString("response.welcome")
                  + " "
                  + Encode.forHtml(signedInUser)
                  + "</h2>"
                  + "<p>"
                  + bundle.getString("response.resultKey")
                  + " <a>"
                  + userKey
                  + "</a>"
                  + "</p>";
        } else {
          // Same message whether the user name or the password was wrong, and never show the
          // account's email address, which is what the password reset function asks for
          log.debug("Incorrect credentials");
          userAddress = bundle.getString("response.badCredentials") + "<br/>";
          htmlOutput = makeTable(userAddress, bundle);
        }
        Database.closeConnection(conn);
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

  private static String makeTable(String userAddress, ResourceBundle bundle) {
    return "<table>"
        + userAddress
        + "<tr><td>"
        + bundle.getString("form.userName")
        + "</td><td><input type='text' id='subName'/></td></tr>"
        + "<tr><td>"
        + bundle.getString("form.password")
        + "</td><td><input type='password' id='subPassword'/></td></tr>"
        + "<tr><td colspan='2'><div id='submitButton'><input type='submit' value='"
        + bundle.getString("form.signIn")
        + "'/>"
        + "</div></td></tr>"
        + "</table>";
  }
}

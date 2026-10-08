package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Failure to Restrict URL Access Challenge 1 (Admin) <br>
 * <br>
 * This class is the target functionality for the challenge. The information required to find this
 * admin function is contained in the JavaScript of the JSP page associated with the level. This
 * level returns a user specific key. <br>
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
public class UrlAccess1Admin extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(UrlAccess1Admin.class);
  private static String levelName = "URL Access 1 (Admin)"; // Used for Logging

  /**
   * This class is the Admin Level Function Call that does not work correctly from the level's view
   * without manipulation. The player must construct the request to this servlet by using the
   * JavaScript Ajax Method as a blueprint This is not the correct function to target to retrieve
   * the Result Key
   */
  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);

    // Translation Stuff
    Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
    ResourceBundle bundle =
        ResourceBundle.getBundle("i18n.servlets.challenges.urlAccess.urlAccess1", locale);

    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      // There is no administrator role in this sub application that a player can hold, so the
      // admin status function is closed to every user. The decision is made on the server and
      // does not depend on anything the client submits.
      log.warn(levelName + " admin function denied to " + ses.getAttribute("userName"));
      response.setStatus(HttpServletResponse.SC_FORBIDDEN);
      String htmlOutput =
          "<h2 class='title'>"
              + bundle.getString("response.accessDenied")
              + "</h2>"
              + "<p>"
              + bundle.getString("response.accessDenied.message")
              + "</p>";
      log.debug("Outputting HTML");
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }
}

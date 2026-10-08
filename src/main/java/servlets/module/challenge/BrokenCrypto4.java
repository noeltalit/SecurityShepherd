package servlets.module.challenge;

import dbProcs.Database;
import dbProcs.Getter;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.ResourceBundle;
import java.util.Set;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import utils.Hash;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Level : Broken Crypto 4 <br>
 * <br>
 *
 * <p>This file is part of the Security Shepherd Project.
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
public class BrokenCrypto4 extends HttpServlet {

  private static final String levelName = new String("Broken Crypto 4");
  private static final String levelHash =
      new String("b927fc4d8c9f70a78f8b6fc46a0cc18533a88b2363054a1f391fe855954d12f9");
  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(BrokenCrypto4.class);

  /*
   * Coupon codes that were shipped to every browser inside couponCheck.js, "protected" only by
   * DES with a key that sat right next to them in the same script. Anybody could decrypt that list,
   * so those codes are compromised and are no longer honoured. Coupons are now only checked on the
   * server and the client script no longer carries any coupon data.
   */
  private static final Set<Integer> REVOKED_COUPON_IDS =
      Collections.unmodifiableSet(new HashSet<Integer>(Arrays.asList(432197)));
  private static final Set<String> REVOKED_COUPON_CODES =
      Collections.unmodifiableSet(new HashSet<String>(Arrays.asList("e!c!3etzoumo@stu4ru176")));
  private static final int MAX_COUPON_LENGTH = 128;

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from
    // proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));
    HttpSession ses = request.getSession(true);
    if (Validate.validateSession(ses)) {
      // Translation Stuff
      Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
      ResourceBundle bundle =
          ResourceBundle.getBundle(
              "i18n.servlets.challenges.insecureCryptoStorage.insecureCryptoStorage", locale);

      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      PrintWriter out = response.getWriter();
      out.print(getServletInfo());
      String htmlOutput = new String();
      String applicationRoot = getServletContext().getRealPath("");
      try {
        // Get and validate cart amounts
        int pineappleAmount =
            validateAmount(Integer.parseInt(request.getParameter("pineappleAmount")));
        log.debug("pineappleAmount - " + pineappleAmount);
        int orangeAmount = validateAmount(Integer.parseInt(request.getParameter("orangeAmount")));
        log.debug("orangeAmount - " + orangeAmount);
        int appleAmount = validateAmount(Integer.parseInt(request.getParameter("appleAmount")));
        log.debug("appleAmount - " + appleAmount);
        int bananaAmount = validateAmount(Integer.parseInt(request.getParameter("bananaAmount")));
        log.debug("bananaAmount - " + bananaAmount);
        String couponCode = request.getParameter("couponCode");
        log.debug("couponCode - " + couponCode);
        if (couponCode == null || couponCode.length() > MAX_COUPON_LENGTH) {
          couponCode = "";
        }

        // Working out costs
        int pineappleCost = pineappleAmount * 30;
        int orangeCost = orangeAmount * 3000;
        int appleCost = appleAmount * 45;
        int bananaCost = bananaAmount * 15;
        int perCentOffPineapple = 0; // Will search for coupons in DB and update this int
        int perCentOffOrange = 0; // Will search for coupons in DB and update this int
        int perCentOffApple = 0; // Will search for coupons in DB and update this int
        int perCentOffBanana = 0; // Will search for coupons in DB and update this int

        htmlOutput = new String();
        if (isRevokedCode(couponCode)) {
          log.debug("Revoked coupon code submitted");
        } else {
          try (Connection conn =
              Database.getChallengeConnection(applicationRoot, "CryptoChallengeShop")) {
            log.debug("Looking for Coupons");
            PreparedStatement prepstmt =
                conn.prepareStatement(
                    "SELECT couponId, itemId, perCentOff, couponCode FROM coupons"
                        + " WHERE couponCode = ?");
            prepstmt.setString(1, couponCode);
            ResultSet coupons = prepstmt.executeQuery();
            if (coupons.next()) {
              int perCentOff = Math.max(0, Math.min(100, coupons.getInt(3)));
              if (REVOKED_COUPON_IDS.contains(coupons.getInt(1))
                  || isRevokedCode(coupons.getString(4))) {
                log.debug("Revoked coupon matched, ignoring it");
              } else if (coupons.getInt(2) == 1) // Pineapple
              {
                log.debug("Found coupon for %" + perCentOff + " off Pineapple");
                perCentOffPineapple = perCentOff;
              } else if (coupons.getInt(2) == 2) // Orange
              {
                log.debug("Found coupon for %" + perCentOff + " off Orange");
                perCentOffOrange = perCentOff;
              } else if (coupons.getInt(2) == 3) // Apple
              {
                log.debug("Found coupon for %" + perCentOff + " off Apple");
                perCentOffApple = perCentOff;
              } else if (coupons.getInt(2) == 4) // Banana
              {
                log.debug("Found coupon for %" + perCentOff + " off Banana");
                perCentOffBanana = perCentOff;
              }
            } else {
              log.debug("Invalid Coupon Code");
            }
          } catch (Exception e) {
            log.debug("Could Not Find Coupon: " + e.toString());
          }
        }

        // Work Out Final Cost
        pineappleCost = pineappleCost - (int) ((long) pineappleCost * perCentOffPineapple / 100);
        appleCost = appleCost - (int) ((long) appleCost * perCentOffApple / 100);
        bananaCost = bananaCost - (int) ((long) bananaCost * perCentOffBanana / 100);
        orangeCost = orangeCost - (int) ((long) orangeCost * perCentOffOrange / 100);
        int finalCost = pineappleCost + appleCost + bananaCost + orangeCost;

        // Output Order
        htmlOutput =
            "<h3>"
                + bundle.getString("insecureCryptoStorage.4.orderComplete")
                + "</h3>"
                + "<p>"
                + bundle.getString("insecureCryptoStorage.4.orderShipped")
                + "<br/></p>"
                + "<p>"
                + bundle.getString("insecureCryptoStorage.4.totalCost")
                + " <a><strong>$"
                + finalCost
                + "</strong></a></p>";
        if (orangeAmount > 0 && orangeCost == 0) {
          htmlOutput +=
              "<p>"
                  + bundle.getString("insecureCryptoStorage.4.freeOranges")
                  + " - "
                  + Hash.generateUserSolution(
                      Getter.getModuleResultFromHash(
                          getServletContext().getRealPath(""), levelHash),
                      (String) ses.getAttribute("userName"))
                  + "</p>";
        }

      } catch (Exception e) {
        log.debug("Didn't complete order: " + e.toString());
        htmlOutput += "<p>" + bundle.getString("insecureCryptoStorage.4.orderFailed") + "</p>";
      }
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }

  private static boolean isRevokedCode(String code) {
    return code != null && REVOKED_COUPON_CODES.contains(code.trim().toLowerCase(Locale.ROOT));
  }

  private static int validateAmount(int amount) {
    if (amount < 0 || amount > 9000) {
      amount = 0;
    }
    return amount;
  }
}

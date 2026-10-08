package servlets.module.challenge;

import java.io.IOException;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Locale;
import java.util.ResourceBundle;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.codec.binary.Base64;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.owasp.encoder.Encode;
import utils.ShepherdLogManager;
import utils.Validate;

/**
 * Bad Crypto Challenge Three. Decrypts messages that were encrypted by this server with AES-GCM
 * under a key that only the server holds <br>
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
public class BrokenCrypto3 extends HttpServlet {

  private static final long serialVersionUID = 1L;
  private static final Logger log = LogManager.getLogger(BrokenCrypto3.class);
  private static String levelName = "Broken Crypto Challenge 3";
  public static String levelHash =
      "2da053b4afb1530a500120a49a14d422ea56705a7e3fc405a77bc269948ccae1";

  /*
   * This level used to "encrypt" with a repeating-key XOR whose key was the level's result key, and
   * it decrypted anything it was sent. Decrypting a run of zero bytes (or any known plain text)
   * handed back the key itself. Messages are now protected with AES-GCM under a random key that is
   * generated on the server, never leaves it, and is unrelated to the result key. Cipher text that
   * was not produced by this server fails authentication and is refused, so the endpoint can no
   * longer be used as an oracle that leaks key material.
   */
  private static final String CIPHER = "AES/GCM/NoPadding";
  private static final int IV_LENGTH = 12;
  private static final int TAG_BITS = 128;
  private static final int MAX_INPUT_LENGTH = 4096;
  private static final SecureRandom RANDOM = new SecureRandom();
  private static final SecretKey SERVER_KEY = newKey();

  /** Example message shown on the challenge page, encrypted with the server-held key. */
  public static final String EXAMPLE_CIPHERTEXT = encryptOrEmpty("This crypto is not strong");

  public void doPost(HttpServletRequest request, HttpServletResponse response)
      throws ServletException, IOException {
    // Setting IpAddress To Log and taking header for original IP if forwarded from proxy
    ShepherdLogManager.setRequestIp(request.getRemoteAddr(), request.getHeader("X-Forwarded-For"));

    HttpSession ses = request.getSession(true);
    if (Validate.validateSession(ses)) {
      ShepherdLogManager.setRequestIp(
          request.getRemoteAddr(),
          request.getHeader("X-Forwarded-For"),
          ses.getAttribute("userName").toString());
      log.debug(levelName + " servlet accessed by: " + ses.getAttribute("userName").toString());
      String htmlOutput = new String();

      PrintWriter out = response.getWriter();
      out.print(getServletInfo());

      // Translation Stuff
      Locale locale = new Locale(Validate.validateLanguage(request.getSession()));
      ResourceBundle bundle =
          ResourceBundle.getBundle(
              "i18n.servlets.challenges.insecureCryptoStorage.insecureCryptoStorage", locale);
      String userData = request.getParameter("userData");
      log.debug("User Submitted - " + userData);

      String decryptedUserData = decrypt(userData);
      if (decryptedUserData != null) {
        htmlOutput =
            "<h2 class='title'>"
                + bundle.getString("insecureCryptoStorage.3.plaintextResult")
                + "</h2><p>"
                + bundle.getString("insecureCryptoStorage.3.plaintextResult.message")
                + "<br/><br/><em>"
                + Encode.forHtml(decryptedUserData)
                + "</em></p>";
      } else {
        log.debug("Cipher text rejected: not produced by this server");
        htmlOutput =
            "<h2 class='title'>"
                + bundle.getString("insecureCryptoStorage.3.plaintextResult")
                + "</h2><p>"
                + bundle.getString("insecureCryptoStorage.3.decryptFailed")
                + "</p>";
      }
      out.write(htmlOutput);
    } else {
      log.error(levelName + " servlet accessed with no session");
    }
  }

  /**
   * Encrypts a message with the server-held key
   *
   * @param plainText Message to encrypt
   * @return Base64 of the IV followed by the AES-GCM cipher text and tag
   * @throws GeneralSecurityException If the JVM cannot perform AES-GCM
   */
  public static String encrypt(String plainText) throws GeneralSecurityException {
    byte[] iv = new byte[IV_LENGTH];
    RANDOM.nextBytes(iv);
    Cipher cipher = Cipher.getInstance(CIPHER);
    cipher.init(Cipher.ENCRYPT_MODE, SERVER_KEY, new GCMParameterSpec(TAG_BITS, iv));
    byte[] cipherText = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    byte[] output = new byte[iv.length + cipherText.length];
    System.arraycopy(iv, 0, output, 0, iv.length);
    System.arraycopy(cipherText, 0, output, iv.length, cipherText.length);
    return Base64.encodeBase64String(output);
  }

  /**
   * Decrypts and authenticates cipher text produced by {@link #encrypt(String)}
   *
   * @param cipherText Base64 cipher text
   * @return The plain text, or null if the input is not authentic cipher text from this server
   */
  public static String decrypt(String cipherText) {
    if (cipherText == null || cipherText.length() > MAX_INPUT_LENGTH) {
      return null;
    }
    String trimmed = cipherText.trim();
    if (!Base64.isBase64(trimmed)) {
      return null;
    }
    byte[] input = Base64.decodeBase64(trimmed);
    if (input.length < IV_LENGTH + TAG_BITS / 8) {
      return null;
    }
    try {
      Cipher cipher = Cipher.getInstance(CIPHER);
      cipher.init(
          Cipher.DECRYPT_MODE, SERVER_KEY, new GCMParameterSpec(TAG_BITS, input, 0, IV_LENGTH));
      byte[] plain = cipher.doFinal(input, IV_LENGTH, input.length - IV_LENGTH);
      return new String(plain, StandardCharsets.UTF_8);
    } catch (GeneralSecurityException | IllegalArgumentException e) {
      return null;
    }
  }

  private static SecretKey newKey() {
    byte[] key = new byte[16];
    RANDOM.nextBytes(key);
    return new SecretKeySpec(key, "AES");
  }

  private static String encryptOrEmpty(String plainText) {
    try {
      return encrypt(plainText);
    } catch (GeneralSecurityException e) {
      log.error("Could not encrypt example message: " + e.toString());
      return "";
    }
  }
}

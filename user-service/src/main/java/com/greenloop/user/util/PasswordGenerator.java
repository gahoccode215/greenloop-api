package com.greenloop.user.util;

import java.security.SecureRandom;
import org.springframework.stereotype.Component;

@Component
public class PasswordGenerator {

  private static final String UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  private static final String LOWERCASE = "abcdefghijklmnopqrstuvwxyz";
  private static final String DIGITS = "0123456789";
  private static final String SPECIAL_CHARS = "@$!%*?&#";
  private static final String ALL_CHARS = UPPERCASE + LOWERCASE + DIGITS + SPECIAL_CHARS;

  private final SecureRandom random = new SecureRandom();

  /**
   * Generate secure random temporary password Format: Min 12 chars với ít nhất 1 uppercase, 1
   * lowercase, 1 digit, 1 special char
   */
  public String generateTemporaryPassword() {
    StringBuilder password = new StringBuilder(12);

    // Đảm bảo có ít nhất 1 ký tự mỗi loại
    password.append(UPPERCASE.charAt(random.nextInt(UPPERCASE.length())));
    password.append(LOWERCASE.charAt(random.nextInt(LOWERCASE.length())));
    password.append(DIGITS.charAt(random.nextInt(DIGITS.length())));
    password.append(SPECIAL_CHARS.charAt(random.nextInt(SPECIAL_CHARS.length())));

    // Fill remaining 8 chars
    for (int i = 0; i < 8; i++) {
      password.append(ALL_CHARS.charAt(random.nextInt(ALL_CHARS.length())));
    }

    // Shuffle để tránh pattern
    return shuffleString(password.toString());
  }

  private String shuffleString(String input) {
    char[] chars = input.toCharArray();
    for (int i = chars.length - 1; i > 0; i--) {
      int j = random.nextInt(i + 1);
      char temp = chars[i];
      chars[i] = chars[j];
      chars[j] = temp;
    }
    return new String(chars);
  }
}

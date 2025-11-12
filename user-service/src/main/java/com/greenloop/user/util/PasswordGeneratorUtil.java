package com.greenloop.user.util;

import java.security.SecureRandom;
import org.springframework.stereotype.Component;

@Component
public class PasswordGeneratorUtil {

    private static final SecureRandom RANDOM = new SecureRandom();

    public String generatePassword() {
        final int length = 8;
        String lowercase = "abcdefghijklmnopqrstuvwxyz";
        String uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String digits = "0123456789";
        String allChars = lowercase + uppercase + digits;

        StringBuilder password = new StringBuilder(length);

        // Bắt buộc 1 ký tự chữ thường, chữ hoa, số
        password.append(lowercase.charAt(RANDOM.nextInt(lowercase.length())));
        password.append(uppercase.charAt(RANDOM.nextInt(uppercase.length())));
        password.append(digits.charAt(RANDOM.nextInt(digits.length())));

        // Phần còn lại
        for (int i = 3; i < length; i++) {
            password.append(allChars.charAt(RANDOM.nextInt(allChars.length())));
        }

        return shuffleString(password.toString());
    }

    private String shuffleString(String input) {
        char[] characters = input.toCharArray();
        for (int i = characters.length - 1; i > 0; i--) {
            int j = RANDOM.nextInt(i + 1);
            char temp = characters[i];
            characters[i] = characters[j];
            characters[j] = temp;
        }
        return new String(characters);
    }
}

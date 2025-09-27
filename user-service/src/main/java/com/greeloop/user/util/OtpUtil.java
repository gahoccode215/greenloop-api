package com.greeloop.user.util;

import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import java.security.SecureRandom;
import java.time.LocalDateTime;

@Component
public class OtpUtil {

    private static final int OTP_LENGTH = 6;
    private static final int OTP_EXPIRY_MINUTES = 5;
    private final SecureRandom random = new SecureRandom();

    public String generateOtp() {
        StringBuilder otp = new StringBuilder();
        for (int i = 0; i < OTP_LENGTH; i++) {
            otp.append(random.nextInt(10));
        }
        return otp.toString();
    }

    public LocalDateTime getOtpExpiryTime() {
        return LocalDateTime.now().plusMinutes(OTP_EXPIRY_MINUTES);
    }

    public boolean isOtpExpired(LocalDateTime otpExpiresAt) {
        return LocalDateTime.now().isAfter(otpExpiresAt);
    }
}

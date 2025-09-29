package com.greenloop.notification;

import com.greenloop.notification.payload.PasswordResetEvent;
import com.greenloop.notification.payload.UserRegistrationEvent;
import com.greenloop.notification.service.MailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

import java.util.function.Consumer;

@Service
@Slf4j
@RequiredArgsConstructor
public class AuthEventConsumer {

    private final MailService mailService;

    @Bean
    public Consumer<UserRegistrationEvent> userRegistrationConsumer() {
        return event -> {
            log.info("Received user registration event: {}", event.getEmail());
            log.info("Received user registration event: {}", event.getOtpCode());
            mailService.sendVerificationEmail(event.getEmail(), event.getOtpCode());
        };
    }

    @Bean
    public Consumer<PasswordResetEvent> passwordResetConsumer() {
        return event -> {
            log.info("Received password reset event: {}", event.getEmail());
            log.info("Password reset OTP: {}", event.getOtpCode());
            mailService.sendPasswordResetEmail(event.getEmail(), event.getOtpCode());
        };
    }

}

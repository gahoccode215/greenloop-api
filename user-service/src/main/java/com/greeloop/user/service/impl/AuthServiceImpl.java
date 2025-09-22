package com.greeloop.user.service.impl;

import com.greeloop.user.constant.RoleConstants;
import com.greeloop.user.dto.request.LoginRequest;
import com.greeloop.user.dto.request.RegisterRequest;
import com.greeloop.user.dto.response.AuthResponse;
import com.greeloop.user.entity.Role;
import com.greeloop.user.entity.User;
import com.greeloop.user.exception.AccountDisabledException;
import com.greeloop.user.exception.EmailAlreadyExistsException;
import com.greeloop.user.exception.InvalidCredentialsException;
import com.greeloop.user.exception.RoleNotFoundException;
import com.greeloop.user.repository.RoleRepository;
import com.greeloop.user.repository.UserRepository;
import com.greeloop.user.service.AuthService;
import com.greeloop.user.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthServiceImpl implements AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;


    @Override
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(InvalidCredentialsException::new);

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new InvalidCredentialsException();
        }

        if (!user.getIsActive()) {
            throw new AccountDisabledException();
        }

        // Generate JWT token
        String token = jwtUtil.generateToken(user);

        log.info("User logged in: {}", user.getEmail());

        return AuthResponse.builder()
                .token(token)
                .type("Bearer")
                .userId(user.getId())
                .email(user.getEmail())
                .role(user.getRole().getName())
                .expiresIn(jwtUtil.getExpirationTime())
                .build();
    }

    @Transactional
    @Override
    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException(request.getEmail());
        }

        Role userRole = roleRepository.findByName(RoleConstants.USER)
                .orElseThrow(() -> new RoleNotFoundException(RoleConstants.USER));

        User user = User.builder()
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(userRole)
                .isActive(true)
                .build();

        user = userRepository.save(user);
        String token = jwtUtil.generateToken(user);

        log.info("New user registered: {}", user.getEmail());

        return AuthResponse.builder()
                .token(token)
                .type("Bearer")
                .userId(user.getId())
                .email(user.getEmail())
                .role(user.getRole().getName())
                .expiresIn(jwtUtil.getExpirationTime())
                .build();
    }
}

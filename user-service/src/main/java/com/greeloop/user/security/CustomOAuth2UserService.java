package com.greeloop.user.security;

import com.greeloop.user.constant.RoleConstants;
import com.greeloop.user.entity.Role;
import com.greeloop.user.entity.User;
import com.greeloop.user.repository.RoleRepository;
import com.greeloop.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) {
        OAuth2User oAuth2User = super.loadUser(userRequest);
        String email = oAuth2User.getAttribute("email");
        User user = userRepository.findByEmail(email).orElse(null);
        Role role = roleRepository.findByName(RoleConstants.USER).orElse(null);
        if (user != null) {
            // Trường hợp: Đã có user với LOCAL provider
            if ("LOCAL".equals(user.getProvider())) {
                throw new OAuth2AuthenticationException(new OAuth2Error("account_exists"));
            }

            // Đã có user với GOOGLE provider - OK
            if ("GOOGLE".equals(user.getProvider())) {
                return oAuth2User;
            }
        }else {
            User newUser = User.builder()
                    .email(email)
                    .isEmailVerified(true)
                    .isActive(true)
                    .role(role)
                    .provider("GOOGLE")
                    .build();
            userRepository.save(newUser);
        }
        return oAuth2User;
    }
}

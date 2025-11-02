package com.greenloop.user.config;

import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@Component
public class CloudinaryConfig {
  @Value("${spring.cloudinary.cloudName}")
  private String cloudName;

  @Value("${spring.cloudinary.apiKey}")
  private String apiKey;

  @Value("${spring.cloudinary.apiSecret}")
  private String apiSecret;

  @Bean
  public Cloudinary cloudinary() {
    return new Cloudinary(
        ObjectUtils.asMap(
            "cloud_name", cloudName, "api_key", apiKey, "api_secret", apiSecret, "secure", true));
  }
}

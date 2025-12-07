package com.greenloop.notification.config;

import com.google.auth.oauth2.GoogleCredentials;
import com.google.firebase.FirebaseApp;
import com.google.firebase.FirebaseOptions;
import java.io.FileInputStream;
import java.io.IOException;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class FirebaseConfig {

  @Bean
  public FirebaseApp initializeFirebase() throws IOException {
    String firebaseConfigPath = System.getenv("FIREBASE_CONFIG");
    if (firebaseConfigPath == null) {
      throw new IllegalStateException("FIREBASE_CONFIG env not set");
    }

    try (FileInputStream serviceAccount = new FileInputStream(firebaseConfigPath)) {
      FirebaseOptions options =
          FirebaseOptions.builder()
              .setCredentials(GoogleCredentials.fromStream(serviceAccount))
              .build();

      if (FirebaseApp.getApps().isEmpty()) {
        return FirebaseApp.initializeApp(options);
      } else {
        return FirebaseApp.getInstance();
      }
    }
  }
}

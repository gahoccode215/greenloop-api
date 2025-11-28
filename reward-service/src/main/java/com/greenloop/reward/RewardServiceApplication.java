package com.greenloop.reward;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class RewardServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(RewardServiceApplication.class, args);
    }
}

package com.example.phishing;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point of the Rule-Based Phishing Email Detection System.
 *
 * This application uses ONLY predefined rules, keyword matching and
 * a points-based risk scoring system to classify emails as
 * SAFE, SUSPICIOUS or PHISHING. No AI/ML is used anywhere.
 */
@SpringBootApplication
public class PhishingEmailDetectionApplication {

    public static void main(String[] args) {
        SpringApplication.run(PhishingEmailDetectionApplication.class, args);
        System.out.println("=========================================================");
        System.out.println(" Phishing Email Detection System started successfully!");
        System.out.println(" Open your browser at: http://localhost:8080");
        System.out.println("=========================================================");
    }
}

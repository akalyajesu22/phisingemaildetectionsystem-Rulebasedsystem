package com.example.phishing.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * JPA Entity representing a single analyzed email and its result.
 * Maps to the "email_analysis" table in the SQLite database.
 */
@Entity
@Table(name = "email_analysis")
public class EmailAnalysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "sender_email", nullable = false)
    private String senderEmail;

    @Column(name = "subject", nullable = false)
    private String subject;

    @Lob
    @Column(name = "email_body", nullable = false)
    private String emailBody;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Column(name = "classification", nullable = false)
    private String classification;

    @Lob
    @Column(name = "detected_indicators")
    private String detectedIndicators; // stored as a "|" separated string

    @Column(name = "analyzed_at", nullable = false)
    private LocalDateTime analyzedAt;

    public EmailAnalysis() {
    }

    public EmailAnalysis(String senderEmail, String subject, String emailBody,
                          int riskScore, String classification,
                          String detectedIndicators, LocalDateTime analyzedAt) {
        this.senderEmail = senderEmail;
        this.subject = subject;
        this.emailBody = emailBody;
        this.riskScore = riskScore;
        this.classification = classification;
        this.detectedIndicators = detectedIndicators;
        this.analyzedAt = analyzedAt;
    }

    // ---------- Getters and Setters ----------

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSenderEmail() {
        return senderEmail;
    }

    public void setSenderEmail(String senderEmail) {
        this.senderEmail = senderEmail;
    }

    public String getSubject() {
        return subject;
    }

    public void setSubject(String subject) {
        this.subject = subject;
    }

    public String getEmailBody() {
        return emailBody;
    }

    public void setEmailBody(String emailBody) {
        this.emailBody = emailBody;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }

    public String getClassification() {
        return classification;
    }

    public void setClassification(String classification) {
        this.classification = classification;
    }

    public String getDetectedIndicators() {
        return detectedIndicators;
    }

    public void setDetectedIndicators(String detectedIndicators) {
        this.detectedIndicators = detectedIndicators;
    }

    public LocalDateTime getAnalyzedAt() {
        return analyzedAt;
    }

    public void setAnalyzedAt(LocalDateTime analyzedAt) {
        this.analyzedAt = analyzedAt;
    }
}

package com.example.phishing.dto;

import java.util.List;

/**
 * DTO representing the response returned after analyzing an email.
 */
public class AnalysisResponse {

    private Long id;
    private String senderEmail;
    private String subject;
    private int riskScore;
    private String classification;
    private List<String> detectedIndicators;
    private String explanation;
    private String analyzedAt;

    public AnalysisResponse() {
    }

    public AnalysisResponse(Long id, String senderEmail, String subject, int riskScore,
                             String classification, List<String> detectedIndicators,
                             String explanation, String analyzedAt) {
        this.id = id;
        this.senderEmail = senderEmail;
        this.subject = subject;
        this.riskScore = riskScore;
        this.classification = classification;
        this.detectedIndicators = detectedIndicators;
        this.explanation = explanation;
        this.analyzedAt = analyzedAt;
    }

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

    public List<String> getDetectedIndicators() {
        return detectedIndicators;
    }

    public void setDetectedIndicators(List<String> detectedIndicators) {
        this.detectedIndicators = detectedIndicators;
    }

    public String getExplanation() {
        return explanation;
    }

    public void setExplanation(String explanation) {
        this.explanation = explanation;
    }

    public String getAnalyzedAt() {
        return analyzedAt;
    }

    public void setAnalyzedAt(String analyzedAt) {
        this.analyzedAt = analyzedAt;
    }
}

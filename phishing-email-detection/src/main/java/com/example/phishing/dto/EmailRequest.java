package com.example.phishing.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

/**
 * DTO representing the incoming request body for POST /api/emails/analyze
 */
public class EmailRequest {

    @NotBlank(message = "Sender email is required")
    @Email(message = "Sender email must be a valid email address")
    private String senderEmail;

    @NotBlank(message = "Subject is required")
    private String subject;

    @NotBlank(message = "Email body is required")
    private String emailBody;

    public EmailRequest() {
    }

    public EmailRequest(String senderEmail, String subject, String emailBody) {
        this.senderEmail = senderEmail;
        this.subject = subject;
        this.emailBody = emailBody;
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
}

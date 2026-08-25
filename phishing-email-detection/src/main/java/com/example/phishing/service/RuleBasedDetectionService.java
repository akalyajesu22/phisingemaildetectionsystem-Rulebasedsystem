package com.example.phishing.service;

import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * RuleBasedDetectionService
 * --------------------------
 * This is the MAIN detection engine of the project.
 *
 * IMPORTANT: This class does NOT use any AI, ML or external API.
 * It only uses:
 *   - keyword matching
 *   - regular expressions
 *   - simple heuristics (uppercase ratio, special character count, etc.)
 *   - a predefined points-based scoring table
 *
 * The final score (0-100) is mapped to SAFE / SUSPICIOUS / PHISHING.
 */
@Service
public class RuleBasedDetectionService {

    // ---------- Rule keyword dictionaries ----------

    private static final String[] URGENT_KEYWORDS = {
            "urgent", "immediately", "action required", "act now",
            "account will be blocked", "account will be suspended",
            "verify now", "respond immediately"
    };

    private static final String[] PASSWORD_KEYWORDS = {
            "password", "confirm password", "verify password",
            "login credentials", "username and password"
    };

    private static final String[] OTP_KEYWORDS = {
            "otp", "one time password", "verification code",
            "security code", "authentication code"
    };

    private static final String[] FINANCIAL_KEYWORDS = {
            "bank account", "credit card", "debit card", "cvv",
            "pin", "payment details", "account number", "transaction"
    };

    private static final String[] SUSPICIOUS_LINK_KEYWORDS = {
            "http://", "bit.ly", "tinyurl", "goo.gl", "t.co", "is.gd", "ow.ly"
    };

    // Matches a raw IPv4 address used as a link host, e.g. http://192.168.1.5/login
    private static final Pattern IP_URL_PATTERN =
            Pattern.compile("https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}");

    private static final String[] PRIZE_KEYWORDS = {
            "congratulations", "you won", "lottery", "prize", "reward",
            "free money", "claim now", "lucky winner"
    };

    private static final String[] THREATENING_KEYWORDS = {
            "account blocked", "account suspended", "legal action",
            "penalty", "fine", "warning", "security alert"
    };

    // Known trusted-brand keywords used to detect sender/organization mismatch
    private static final String[] BRAND_KEYWORDS = {
            "paypal", "amazon", "google", "microsoft", "apple", "bank",
            "netflix", "facebook", "instagram"
    };

    /**
     * Holds the result of one detection rule engine run.
     */
    public static class DetectionResult {
        private int riskScore;
        private String classification;
        private List<String> detectedIndicators = new ArrayList<>();
        private String explanation;

        public int getRiskScore() { return riskScore; }
        public void setRiskScore(int riskScore) { this.riskScore = riskScore; }

        public String getClassification() { return classification; }
        public void setClassification(String classification) { this.classification = classification; }

        public List<String> getDetectedIndicators() { return detectedIndicators; }
        public void setDetectedIndicators(List<String> detectedIndicators) { this.detectedIndicators = detectedIndicators; }

        public String getExplanation() { return explanation; }
        public void setExplanation(String explanation) { this.explanation = explanation; }
    }

    /**
     * Main entry point: analyzes sender, subject and body and returns
     * a full DetectionResult containing score, classification, indicators
     * and a human-readable explanation.
     */
    public DetectionResult analyze(String senderEmail, String subject, String emailBody) {
        int score = 0;
        List<String> indicators = new ArrayList<>();

        String combinedText = (safe(subject) + " " + safe(emailBody)).toLowerCase();

        // Rule 1: Urgent language (+10)
        if (containsAny(combinedText, URGENT_KEYWORDS)) {
            score += 10;
            indicators.add("Urgent language detected");
        }

        // Rule 2: Password request (+20)
        if (containsAny(combinedText, PASSWORD_KEYWORDS)) {
            score += 20;
            indicators.add("Password request detected");
        }

        // Rule 3: OTP request (+20)
        if (containsAny(combinedText, OTP_KEYWORDS)) {
            score += 20;
            indicators.add("OTP request detected");
        }

        // Rule 4: Financial information request (+20)
        if (containsAny(combinedText, FINANCIAL_KEYWORDS)) {
            score += 20;
            indicators.add("Financial information request detected");
        }

        // Rule 5: Suspicious links (+20)
        if (containsAny(combinedText, SUSPICIOUS_LINK_KEYWORDS) || IP_URL_PATTERN.matcher(combinedText).find()) {
            score += 20;
            indicators.add("Suspicious URL detected");
        }

        // Rule 6: Prize / reward / scam language (+15)
        if (containsAny(combinedText, PRIZE_KEYWORDS)) {
            score += 15;
            indicators.add("Prize/reward scam language detected");
        }

        // Rule 7: Threatening language (+10)
        if (containsAny(combinedText, THREATENING_KEYWORDS)) {
            score += 10;
            indicators.add("Threatening language detected");
        }

        // Rule 8: Suspicious sender (+15)
        if (isSuspiciousSender(senderEmail, combinedText)) {
            score += 15;
            indicators.add("Suspicious sender address detected");
        }

        // Rule 9: Excessive capital letters (+5)
        if (hasExcessiveCapitalLetters(safe(subject) + " " + safe(emailBody))) {
            score += 5;
            indicators.add("Excessive use of capital letters detected");
        }

        // Rule 10: Excessive special characters (+5)
        if (hasExcessiveSpecialCharacters(safe(subject) + " " + safe(emailBody))) {
            score += 5;
            indicators.add("Excessive special characters detected");
        }

        // Clamp final score between 0 and 100
        if (score > 100) score = 100;
        if (score < 0) score = 0;

        String classification = classify(score);
        String explanation = buildExplanation(classification, indicators.size());

        DetectionResult result = new DetectionResult();
        result.setRiskScore(score);
        result.setClassification(classification);
        result.setDetectedIndicators(indicators);
        result.setExplanation(explanation);
        return result;
    }

    // ---------- Helper / rule-check methods ----------

    private String safe(String s) {
        return s == null ? "" : s;
    }

    private boolean containsAny(String text, String[] keywords) {
        for (String keyword : keywords) {
            if (text.contains(keyword.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Rule 8 helper: flags a sender as suspicious if
     *   - the email format itself is invalid, OR
     *   - the domain contains random/lookalike characters (digit substituted for letter,
     *     e.g. "paypa1"), OR
     *   - the email body claims to be from a well-known brand but the sender domain
     *     does not actually belong to that brand.
     */
    private boolean isSuspiciousSender(String senderEmail, String combinedText) {
        if (senderEmail == null || senderEmail.isBlank()) {
            return true;
        }

        String email = senderEmail.trim().toLowerCase();

        // Basic format check
        Pattern emailPattern = Pattern.compile("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$");
        if (!emailPattern.matcher(email).matches()) {
            return true;
        }

        String domain = email.substring(email.indexOf('@') + 1);

        // Lookalike domain check: digits mixed inside an otherwise alphabetic domain
        // e.g. paypa1-security.com, amaz0n-support.net
        String domainName = domain.split("\\.")[0];
        boolean hasDigit = domainName.chars().anyMatch(Character::isDigit);
        boolean hasLetter = domainName.chars().anyMatch(Character::isLetter);
        if (hasDigit && hasLetter) {
            return true;
        }

        // Brand mismatch check: body/subject mentions a known brand,
        // but the sender's domain does not contain that brand name.
        for (String brand : BRAND_KEYWORDS) {
            if (combinedText.contains(brand) && !domain.contains(brand)) {
                return true;
            }
        }

        // Excessive hyphens or overly long domain often indicates a crafted phishing domain
        long hyphenCount = domain.chars().filter(c -> c == '-').count();
        if (hyphenCount >= 2) {
            return true;
        }

        return false;
    }

    /**
     * Rule 9 helper: if more than 30% of alphabetic characters are uppercase
     * (and there are a meaningful number of letters), flag as excessive.
     */
    private boolean hasExcessiveCapitalLetters(String text) {
        long letters = text.chars().filter(Character::isLetter).count();
        if (letters < 15) return false; // not enough text to judge

        long uppercase = text.chars().filter(Character::isUpperCase).count();
        double ratio = (double) uppercase / letters;
        return ratio > 0.3;
    }

    /**
     * Rule 10 helper: flags excessive use of symbols like !!!, ???, $$$, @@ etc.
     */
    private boolean hasExcessiveSpecialCharacters(String text) {
        Matcher exclaim = Pattern.compile("!{2,}").matcher(text);
        Matcher question = Pattern.compile("\\?{2,}").matcher(text);
        Matcher dollar = Pattern.compile("\\${2,}").matcher(text);
        Matcher atSign = Pattern.compile("@{2,}").matcher(text);

        if (exclaim.find() || question.find() || dollar.find() || atSign.find()) {
            return true;
        }

        long specialCount = text.chars()
                .filter(c -> "!@#$%^&*".indexOf(c) >= 0)
                .count();

        return specialCount >= 6;
    }

    /**
     * Maps the final numeric score to a classification label.
     * SAFE: 0-30, SUSPICIOUS: 31-60, PHISHING: 61-100
     */
    private String classify(int score) {
        if (score <= 30) {
            return "SAFE";
        } else if (score <= 60) {
            return "SUSPICIOUS";
        } else {
            return "PHISHING";
        }
    }

    private String buildExplanation(String classification, int indicatorCount) {
        switch (classification) {
            case "PHISHING":
                return "This email contains multiple phishing indicators (" + indicatorCount +
                        ") and should not be trusted. Do not click links or provide passwords, OTPs or financial information.";
            case "SUSPICIOUS":
                return "Some suspicious indicators were detected (" + indicatorCount +
                        "). Review the email carefully before responding or clicking any links.";
            default:
                return "No significant phishing indicators detected. This email appears to be safe.";
        }
    }
}

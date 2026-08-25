package com.example.phishing.service;

import com.example.phishing.dto.AnalysisResponse;
import com.example.phishing.dto.EmailRequest;
import com.example.phishing.entity.EmailAnalysis;
import com.example.phishing.repository.EmailAnalysisRepository;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

/**
 * Orchestrates the email analysis workflow:
 *   1. Calls the RuleBasedDetectionService to compute score/classification
 *   2. Persists the result to SQLite via the repository
 *   3. Provides history retrieval and dashboard statistics
 */
@Service
public class EmailAnalysisService {

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");
    private static final String INDICATOR_DELIMITER = "\\|";
    private static final String INDICATOR_JOIN = "|";

    private final EmailAnalysisRepository repository;
    private final RuleBasedDetectionService detectionService;

    public EmailAnalysisService(EmailAnalysisRepository repository,
                                 RuleBasedDetectionService detectionService) {
        this.repository = repository;
        this.detectionService = detectionService;
    }

    public AnalysisResponse analyzeAndSave(EmailRequest request) {
        RuleBasedDetectionService.DetectionResult result = detectionService.analyze(
                request.getSenderEmail(), request.getSubject(), request.getEmailBody());

        LocalDateTime now = LocalDateTime.now();

        EmailAnalysis entity = new EmailAnalysis(
                request.getSenderEmail(),
                request.getSubject(),
                request.getEmailBody(),
                result.getRiskScore(),
                result.getClassification(),
                String.join(INDICATOR_JOIN, result.getDetectedIndicators()),
                now
        );

        EmailAnalysis saved = repository.save(entity);

        return toResponse(saved, result.getExplanation());
    }

    public List<AnalysisResponse> getAllHistory() {
        return repository.findAllByOrderByAnalyzedAtDesc()
                .stream()
                .map(e -> toResponse(e, null))
                .collect(Collectors.toList());
    }

    public AnalysisResponse getById(Long id) {
        EmailAnalysis entity = repository.findById(id)
                .orElseThrow(() -> new NoSuchElementException("Email analysis not found with id: " + id));
        return toResponse(entity, null);
    }

    public void deleteById(Long id) {
        if (!repository.existsById(id)) {
            throw new NoSuchElementException("Email analysis not found with id: " + id);
        }
        repository.deleteById(id);
    }

    public DashboardStatistics getStatistics() {
        long total = repository.count();
        long safe = repository.countByClassification("SAFE");
        long suspicious = repository.countByClassification("SUSPICIOUS");
        long phishing = repository.countByClassification("PHISHING");
        return new DashboardStatistics(total, safe, suspicious, phishing);
    }

    private AnalysisResponse toResponse(EmailAnalysis entity, String explanationOverride) {
        List<String> indicators;
        if (entity.getDetectedIndicators() == null || entity.getDetectedIndicators().isBlank()) {
            indicators = List.of();
        } else {
            indicators = Arrays.stream(entity.getDetectedIndicators().split(INDICATOR_DELIMITER))
                    .collect(Collectors.toList());
        }

        String explanation = explanationOverride != null
                ? explanationOverride
                : buildExplanationFromClassification(entity.getClassification(), indicators.size());

        return new AnalysisResponse(
                entity.getId(),
                entity.getSenderEmail(),
                entity.getSubject(),
                entity.getRiskScore(),
                entity.getClassification(),
                indicators,
                explanation,
                entity.getAnalyzedAt().format(FORMATTER)
        );
    }

    private String buildExplanationFromClassification(String classification, int indicatorCount) {
        switch (classification) {
            case "PHISHING":
                return "This email contains multiple phishing indicators (" + indicatorCount +
                        ") and should not be trusted.";
            case "SUSPICIOUS":
                return "Some suspicious indicators were detected (" + indicatorCount + "). Review carefully.";
            default:
                return "No significant phishing indicators detected.";
        }
    }

    /**
     * Simple record-like holder for dashboard statistics.
     */
    public static class DashboardStatistics {
        private long totalAnalyzed;
        private long safe;
        private long suspicious;
        private long phishing;

        public DashboardStatistics(long totalAnalyzed, long safe, long suspicious, long phishing) {
            this.totalAnalyzed = totalAnalyzed;
            this.safe = safe;
            this.suspicious = suspicious;
            this.phishing = phishing;
        }

        public long getTotalAnalyzed() { return totalAnalyzed; }
        public long getSafe() { return safe; }
        public long getSuspicious() { return suspicious; }
        public long getPhishing() { return phishing; }
    }
}

package com.example.phishing.controller;

import com.example.phishing.dto.AnalysisResponse;
import com.example.phishing.dto.EmailRequest;
import com.example.phishing.service.EmailAnalysisService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.*;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

/**
 * REST API for the Phishing Email Detection System.
 *
 * Endpoints:
 *   POST   /api/emails/analyze     - analyze a new email
 *   GET    /api/emails             - get all history
 *   GET    /api/emails/{id}        - get one analysis by id
 *   DELETE /api/emails/{id}        - delete an analysis
 *   GET    /api/emails/statistics  - dashboard statistics
 */
@RestController
@RequestMapping("/api/emails")
public class EmailAnalysisController {

    private final EmailAnalysisService emailAnalysisService;

    public EmailAnalysisController(EmailAnalysisService emailAnalysisService) {
        this.emailAnalysisService = emailAnalysisService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<AnalysisResponse> analyzeEmail(@Valid @RequestBody EmailRequest request) {
        AnalysisResponse response = emailAnalysisService.analyzeAndSave(request);
        return ResponseEntity.ok(response);
    }

    @GetMapping
    public ResponseEntity<List<AnalysisResponse>> getAllHistory() {
        return ResponseEntity.ok(emailAnalysisService.getAllHistory());
    }

    @GetMapping("/{id}")
    public ResponseEntity<AnalysisResponse> getById(@PathVariable Long id) {
        return ResponseEntity.ok(emailAnalysisService.getById(id));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, String>> deleteById(@PathVariable Long id) {
        emailAnalysisService.deleteById(id);
        Map<String, String> response = new LinkedHashMap<>();
        response.put("message", "Email analysis deleted successfully");
        return ResponseEntity.ok(response);
    }

    @GetMapping("/statistics")
    public ResponseEntity<EmailAnalysisService.DashboardStatistics> getStatistics() {
        return ResponseEntity.ok(emailAnalysisService.getStatistics());
    }

    // ---------- Exception Handling ----------

    @ExceptionHandler(NoSuchElementException.class)
    public ResponseEntity<Map<String, String>> handleNotFound(NoSuchElementException ex) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("error", ex.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(body);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> handleValidation(MethodArgumentNotValidException ex) {
        Map<String, String> errors = new LinkedHashMap<>();
        ex.getBindingResult().getFieldErrors().forEach(err ->
                errors.put(err.getField(), err.getDefaultMessage()));
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errors);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, String>> handleGeneric(Exception ex) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("error", "Something went wrong: " + ex.getMessage());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}

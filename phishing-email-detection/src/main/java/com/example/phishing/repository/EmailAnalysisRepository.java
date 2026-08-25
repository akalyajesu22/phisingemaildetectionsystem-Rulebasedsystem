package com.example.phishing.repository;

import com.example.phishing.entity.EmailAnalysis;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Repository for EmailAnalysis entity. Spring Data JPA automatically
 * implements this interface at runtime (no SQL injection risk since
 * all queries are parameterized under the hood).
 */
@Repository
public interface EmailAnalysisRepository extends JpaRepository<EmailAnalysis, Long> {

    List<EmailAnalysis> findAllByOrderByAnalyzedAtDesc();

    long countByClassification(String classification);
}

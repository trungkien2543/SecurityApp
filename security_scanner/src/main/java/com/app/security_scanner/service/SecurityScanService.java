package com.app.security_scanner.service;

import com.app.security_scanner.dto.request.ExecuteRequest;
import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.entity.Finding;
import com.app.security_scanner.entity.Scan;
import com.app.security_scanner.entity.ScanIssue;
import com.app.security_scanner.service.scanner.RateLimitScanner;
import com.app.security_scanner.service.scanner.SecurityScanner;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class SecurityScanService {

    // Spring inject tất cả bean implement SecurityScanner vào đây
    // Day 6 thêm CorsScanner @Component → tự động có trong list này
    private final List<SecurityScanner> scanners;

    private final RateLimitScanner rateLimitScanner;

    public List<ScanIssue> scanAndBuildIssues(
            ExecuteRequest request,   // ← thêm request vào đây
            ExecuteResponse response,
            Scan scan) {

        List<Finding> findings = new ArrayList<>();

        // Chạy passive scanners như bình thường
        findings.addAll(runAllScanners(response));

        // Chạy rate limit scanner riêng vì cần request
        findings.addAll(rateLimitScanner.scanWithRequest(request));

        log.info("Security scan done — {} finding(s) for url={}",
                findings.size(), scan.getTargetUrl());

        return buildIssues(findings, scan);
    }

    private List<Finding> runAllScanners(ExecuteResponse response) {
        return scanners.stream()
                .flatMap(scanner -> {
                    try {
                        List<Finding> results = scanner.scan(response);
                        log.debug("[{}] {} finding(s)",
                                scanner.getClass().getSimpleName(),
                                results.size());
                        return results.stream();
                    } catch (Exception ex) {
                        // Một scanner lỗi không được làm hỏng toàn bộ scan
                        log.error("[{}] failed, skipping",
                                scanner.getClass().getSimpleName(), ex);
                        return java.util.stream.Stream.empty();
                    }
                })
                .collect(Collectors.toList());
    }

    private List<ScanIssue> buildIssues(List<Finding> findings, Scan scan) {
        return findings.stream()
                .map(f -> ScanIssue.builder()
                        .scan(scan)
                        .vulnerability(f.vulnerability())
                        .severity(f.severity())
                        .title(f.title())
                        .description(f.description())
                        .recommendation(f.recommendation())
                        .build())
                .collect(Collectors.toList());
    }
}
package com.app.security_scanner.service.scanner;

import com.app.security_scanner.dto.request.ExecuteRequest;
import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.entity.Finding;
import com.app.security_scanner.enums.Severity;
import com.app.security_scanner.enums.VulnerabilityType;
import com.app.security_scanner.service.RequestExecutorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class RateLimitScanner{

    private final RequestExecutorService requestExecutorService;

    // 15 request đủ để trigger rate limit của hầu hết API
    // Không spam quá nhiều — tránh bị block IP
    private static final int PROBE_COUNT = 15;


    // Method riêng — gọi từ SecurityScanService
    public List<Finding> scanWithRequest(ExecuteRequest request) {
        List<Finding> findings = new ArrayList<>();

        log.info("Rate limit probe: sending {} requests to {}", PROBE_COUNT, request.url());

        boolean hasRateLimit = false;

        for (int i = 0; i < PROBE_COUNT; i++) {
            try {
                ExecuteResponse probeResponse = requestExecutorService.execute(request);

                if (probeResponse.status() == 429) {
                    hasRateLimit = true;
                    log.debug("Rate limit detected at request #{}", i + 1);
                    break; // Confirm rồi, không cần spam tiếp
                }

            } catch (Exception ex) {
                log.warn("Probe request #{} failed: {}", i + 1, ex.getMessage());
            }
        }

        if (!hasRateLimit) {
            findings.add(Finding.builder()
                    .vulnerability(VulnerabilityType.NO_RATE_LIMITING)
                    .severity(Severity.MEDIUM)
                    .title("No Rate Limiting detected")
                    .description(
                            "Gửi " + PROBE_COUNT + " request liên tiếp không nhận được " +
                                    "429 Too Many Requests. API có thể bị brute force, " +
                                    "credential stuffing hoặc DDoS."
                    )
                    .recommendation(
                            "Implement rate limiting. " +
                                    "VD với Spring Boot: dùng Bucket4j hoặc " +
                                    "API Gateway rate limiting."
                    )
                    .build());
        }

        return findings;
    }
}
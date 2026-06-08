package com.app.security_scanner.service.scanner;
import com.app.security_scanner.dto.request.ExecuteRequest;
import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.enums.Severity;
import com.app.security_scanner.enums.VulnerabilityType;
import com.app.security_scanner.model.Finding;
import com.app.security_scanner.service.RequestExecutorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class DangerousMethodScanner {

    private final RequestExecutorService requestExecutorService;

    // Method → severity + mô tả
    private static final Map<String, MethodRule> DANGEROUS_METHODS = Map.of(
            "TRACE", new MethodRule(
                    Severity.HIGH,
                    "TRACE method enabled",
                    "TRACE method được bật — attacker có thể đọc cookie và auth header " +
                            "thông qua Cross-Site Tracing (XST) attack.",
                    "Disable TRACE method. Nginx: limit_except GET POST { deny all; }"
            ),
            "TRACK", new MethodRule(
                    Severity.HIGH,
                    "TRACK method enabled",
                    "TRACK là variant của TRACE dùng trên IIS — tương tự XST attack.",
                    "Disable TRACK method trên IIS server."
            ),
            "DELETE", new MethodRule(
                    Severity.MEDIUM,
                    "DELETE method enabled",
                    "DELETE method được bật trên endpoint này. " +
                            "Nếu không có auth đúng cách, attacker có thể xóa resource.",
                    "Đảm bảo DELETE endpoint được bảo vệ bằng authentication và authorization."
            ),
            "PUT", new MethodRule(
                    Severity.MEDIUM,
                    "PUT method enabled",
                    "PUT method được bật — attacker có thể overwrite resource nếu không có auth.",
                    "Đảm bảo PUT endpoint được bảo vệ bằng authentication và authorization."
            ),
            "CONNECT", new MethodRule(
                    Severity.HIGH,
                    "CONNECT method enabled",
                    "CONNECT method dùng để tạo TCP tunnel — " +
                            "attacker có thể bypass firewall và proxy.",
                    "Disable CONNECT method trừ khi server là proxy."
            )
    );

    public List<Finding> scan(ExecuteRequest originalRequest) {
        List<Finding> findings = new ArrayList<>();

        for (Map.Entry<String, MethodRule> entry : DANGEROUS_METHODS.entrySet()) {
            String method = entry.getKey();
            MethodRule rule = entry.getValue();

            try {
                ExecuteRequest probeRequest = new ExecuteRequest(
                        originalRequest.url(), method, null, null
                );
                ExecuteResponse response = requestExecutorService.execute(probeRequest);

                log.debug("Method probe {} → {}", method, response.status());

                // 200, 201, 204 = server chấp nhận method → nguy hiểm
                // 405 = Method Not Allowed → an toàn
                // 401, 403 = có auth → ít nguy hiểm hơn nhưng vẫn report LOW
                if (isMethodAccepted(response.status())) {
                    findings.add(Finding.builder()
                            .vulnerability(VulnerabilityType.DANGEROUS_METHOD_ALLOWED)
                            .severity(rule.severity())
                            .title(rule.title())
                            .description(rule.description() +
                                    " Server trả về " + response.status() + ".")
                            .recommendation(rule.recommendation())
                            .build());

                    log.warn("Dangerous method accepted: {} → {}", method, response.status());

                } else if (response.status() == 401 || response.status() == 403) {
                    findings.add(Finding.builder()
                            .vulnerability(VulnerabilityType.DANGEROUS_METHOD_ALLOWED)
                            .severity(Severity.LOW)
                            .title(rule.title() + " (auth required)")
                            .description(rule.description() +
                                    " Server trả về " + response.status() +
                                    " — method tồn tại nhưng cần auth.")
                            .recommendation(rule.recommendation())
                            .build());
                }

            } catch (Exception ex) {
                log.debug("Method probe failed for {}: {}", method, ex.getMessage());
            }
        }

        return findings;
    }

    // 2xx = server chấp nhận → nguy hiểm
    private boolean isMethodAccepted(int status) {
        return status >= 200 && status < 300;
    }

    private record MethodRule(
            Severity severity,
            String title,
            String description,
            String recommendation
    ) {
    }
}
package com.app.security_scanner.service.scanner;

import com.app.security_scanner.dto.request.ExecuteRequest;
import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.model.Finding;
import com.app.security_scanner.enums.Severity;
import com.app.security_scanner.enums.VulnerabilityType;
import com.app.security_scanner.service.RequestExecutorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class SwaggerExposureScanner {

    private final RequestExecutorService requestExecutorService;

    private static final List<String> SWAGGER_PATHS = List.of(
            "/swagger-ui",
            "/swagger-ui.html",
            "/swagger-ui/index.html",
            "/v2/api-docs",
            "/v3/api-docs",
            "/swagger",              // ← thêm
            "/swagger/index.html",   // ← thêm
            // với context path /api
            "/api/swagger-ui/index.html",
            "/api/swagger-ui.html",
            "/api/v2/api-docs",
            "/api/v3/api-docs"
    );

    private static final List<String> ACTUATOR_PATHS = List.of(
            "/actuator",
            "/actuator/env",
            "/actuator/beans",
            "/actuator/mappings",
            "/api/actuator",
            "/api/actuator/env"
    );

    public List<Finding> scan(ExecuteRequest originalRequest) {
        List<Finding> findings = new ArrayList<>();
        String baseUrl = extractBaseUrl(originalRequest.url());

        log.info("SwaggerScanner probing baseUrl: {}", baseUrl);

        checkPaths(baseUrl, SWAGGER_PATHS, VulnerabilityType.SWAGGER_EXPOSED,
                Severity.MEDIUM, "Swagger/API docs exposed", findings);

        checkPaths(baseUrl, ACTUATOR_PATHS, VulnerabilityType.ACTUATOR_EXPOSED,
                Severity.HIGH, "Spring Actuator exposed", findings);

        return findings;
    }

    private void checkPaths(
            String baseUrl,
            List<String> paths,
            VulnerabilityType vulnerability,
            Severity severity,
            String titlePrefix,
            List<Finding> findings) {

        for (String path : paths) {
            String fullUrl = baseUrl + path;

            try {
                ExecuteRequest probeRequest = new ExecuteRequest(
                        fullUrl, "GET", null, null
                );
                ExecuteResponse response = requestExecutorService.execute(probeRequest);

                log.info("Probe {} → {}", fullUrl, response.status()); // ← thêm dòng này


                if (response.status() == 200 && isSwaggerExposed(response)) {

                    log.info("Probe {} → 200, body preview: {}",
                            fullUrl,
                            response.body() == null ? "null" :
                                    response.body().substring(0, Math.min(200, response.body().length()))
                    );

                    findings.add(Finding.builder()
                            .vulnerability(vulnerability)
                            .severity(severity)
                            .title(titlePrefix + " exposed: " + path)
                            .description(
                                    "Endpoint " + fullUrl + " trả về 200. " +
                                            getDescription(vulnerability)
                            )
                            .recommendation(getRecommendation(vulnerability))
                            .build());

                    log.warn("Exposed endpoint found: {} (200)", fullUrl);

                } else if (response.status() == 401) {
                    findings.add(Finding.builder()
                            .vulnerability(vulnerability)
                            .severity(Severity.LOW)
                            .title(titlePrefix + " exists but requires auth: " + path)
                            .description(
                                    "Endpoint " + fullUrl + " trả về 401. " +
                                            "Endpoint tồn tại nhưng được bảo vệ bằng auth. " +
                                            "Nên ẩn hoàn toàn trên production."
                            )
                            .recommendation(getRecommendation(vulnerability))
                            .build());

                    log.info("Protected endpoint found: {} (401)", fullUrl);
                }

            } catch (Exception ex) {
                log.error("Probe failed for {}", fullUrl, ex); // ← bỏ ex.getMessage(), chỉ truyền ex
            }
        }
    }

    // Extract base URL — bỏ path, chỉ giữ scheme + host + port
    // VD: https://api.example.com/v1/users → https://api.example.com
    private String extractBaseUrl(String url) {
        try {
            URI uri = URI.create(url);
            return uri.getScheme() + "://" + uri.getHost() +
                    (uri.getPort() != -1 ? ":" + uri.getPort() : "");
        } catch (Exception ex) {
            log.error("Failed to extract base URL from: {}", url);
            return url;
        }
    }

    private String getDescription(VulnerabilityType type) {
        return switch (type) {
            case SWAGGER_EXPOSED -> "Attacker có thể xem toàn bộ API endpoints, parameters, " +
                    "và auth mechanism — giúp tấn công dễ dàng hơn nhiều.";
            case ACTUATOR_EXPOSED -> "Spring Actuator lộ thông tin nhạy cảm: biến môi trường, " +
                    "database credentials, Spring beans, health status.";
            default -> "";
        };
    }

    private String getRecommendation(VulnerabilityType type) {
        return switch (type) {
            case SWAGGER_EXPOSED -> "Disable Swagger trên production: " +
                    "springdoc.swagger-ui.enabled=false trong application-prod.yml";
            case ACTUATOR_EXPOSED -> "Giới hạn Actuator endpoints: " +
                    "management.endpoints.web.exposure.include=health,info " +
                    "và thêm security cho /actuator/**";
            default -> "";
        };
    }

    private boolean isSwaggerExposed(ExecuteResponse response) {
        if (response.status() != 200) return false;

        String body = response.body();
        if (body == null) return false;

        // Dấu hiệu nhận biết Swagger UI
        return body.contains("swagger-ui")
                || body.contains("Swagger UI")
                || body.contains("openapi")
                || body.contains("\"swagger\":")
                || body.contains("\"openapi\":");
    }
}
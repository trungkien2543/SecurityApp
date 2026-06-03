package com.app.security_scanner.service.scanner;

import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.entity.Finding;
import com.app.security_scanner.enums.Severity;
import com.app.security_scanner.enums.VulnerabilityType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
public class CorsScanner extends BaseScanner {

    private static final String ALLOW_ORIGIN = "access-control-allow-origin";
    private static final String ALLOW_CREDENTIALS = "access-control-allow-credentials";
    private static final String ALLOW_METHODS = "access-control-allow-methods";

    private static final List<String> DANGEROUS_METHODS = List.of(
            "DELETE", "TRACE", "CONNECT"
    );

    @Override
    public List<Finding> scan(ExecuteResponse response) {
        List<Finding> findings = new ArrayList<>();
        Map<String, String> headers = normalizeHeaders(response.headers());

        String origin = headers.get(ALLOW_ORIGIN);
        String credentials = headers.get(ALLOW_CREDENTIALS);
        String methods = headers.get(ALLOW_METHODS);

        // Không có CORS header → server không cấu hình CORS → bỏ qua
        if (origin == null) return findings;

        checkWildcardWithCredentials(origin, credentials, findings);
        checkWildcardOnly(origin, credentials, findings);
        checkDangerousMethods(methods, findings);

        return findings;
    }

    // CRITICAL — * kèm credentials=true
    // Bất kỳ site nào đọc được response kèm cookie của nạn nhân
    private void checkWildcardWithCredentials(
            String origin,
            String credentials,
            List<Finding> findings) {

        if ("*".equals(origin) && "true".equalsIgnoreCase(credentials)) {
            findings.add(Finding.builder()
                    .vulnerability(VulnerabilityType.CORS_CREDENTIALS_WILDCARD)
                    .severity(Severity.CRITICAL)
                    .title("CORS: Wildcard origin với credentials")
                    .description(
                            "Server trả Access-Control-Allow-Origin: * kèm " +
                                    "Access-Control-Allow-Credentials: true. " +
                                    "Bất kỳ website nào cũng có thể đọc response kèm cookie của nạn nhân."
                    )
                    .recommendation(
                            "Không dùng wildcard khi enable credentials. " +
                                    "Thay bằng whitelist: Access-Control-Allow-Origin: https://yourapp.com"
                    )
                    .build());
        }
    }

    // MEDIUM — chỉ wildcard, không có credentials
    // Chỉ report nếu chưa report CRITICAL ở trên
    private void checkWildcardOnly(
            String origin,
            String credentials,
            List<Finding> findings) {

        boolean isWildcard = "*".equals(origin);
        boolean hasCredentials = "true".equalsIgnoreCase(credentials);

        if (isWildcard && !hasCredentials) {
            findings.add(Finding.builder()
                    .vulnerability(VulnerabilityType.CORS_WILDCARD)
                    .severity(Severity.MEDIUM)
                    .title("CORS: Wildcard origin")
                    .description(
                            "Access-Control-Allow-Origin: * cho phép bất kỳ website nào " +
                                    "đọc response của API. Nguy hiểm nếu API có authentication."
                    )
                    .recommendation(
                            "Dùng whitelist domain thay vì wildcard. " +
                                    "VD: Access-Control-Allow-Origin: https://yourapp.com"
                    )
                    .build());
        }
    }

    // LOW — expose method nguy hiểm trong CORS context
    private void checkDangerousMethods(String methods, List<Finding> findings) {
        if (methods == null) return;

        String methodsUpper = methods.toUpperCase();

        for (String method : DANGEROUS_METHODS) {
            if (methodsUpper.contains(method)) {
                findings.add(Finding.builder()
                        .vulnerability(VulnerabilityType.DANGEROUS_METHOD_ALLOWED)
                        .severity(Severity.LOW)
                        .title("CORS: Dangerous method exposed — " + method)
                        .description(
                                "Access-Control-Allow-Methods chứa " + method + ". " +
                                        "Cross-origin request từ bất kỳ domain nào có thể trigger method này."
                        )
                        .recommendation(
                                "Chỉ expose method cần thiết: GET, POST, PUT, PATCH, OPTIONS."
                        )
                        .build());
                break;
            }
        }
    }
}
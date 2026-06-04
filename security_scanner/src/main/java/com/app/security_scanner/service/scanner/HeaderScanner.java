package com.app.security_scanner.service.scanner;

import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.model.Finding;
import com.app.security_scanner.enums.Severity;
import com.app.security_scanner.enums.VulnerabilityType;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Component
public class HeaderScanner extends BaseScanner{

    // Static vì rules không thay đổi theo request
    // Final vì không ai được phép sửa list này sau khi khởi tạo
    private static final List<HeaderRule> RULES = List.of(

            new HeaderRule(
                    "content-security-policy",
                    VulnerabilityType.MISSING_CSP,
                    Severity.HIGH,
                    "Missing Content-Security-Policy",
                    "Không có CSP header — browser cho phép load resource từ bất kỳ domain nào, " +
                            "attacker có thể inject script độc hại (XSS).",
                    "Thêm: Content-Security-Policy: default-src 'self'; " +
                            "script-src 'self'; style-src 'self' 'unsafe-inline'"
            ),

            new HeaderRule(
                    "strict-transport-security",
                    VulnerabilityType.MISSING_HSTS,
                    Severity.HIGH,
                    "Missing HTTP Strict Transport Security (HSTS)",
                    "Không có HSTS — browser có thể bị attacker downgrade từ HTTPS về HTTP " +
                            "và chặn toàn bộ traffic (Man-in-the-Middle attack).",
                    "Thêm: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
            ),

            new HeaderRule(
                    "x-frame-options",
                    VulnerabilityType.MISSING_X_FRAME_OPTIONS,
                    Severity.MEDIUM,
                    "Missing X-Frame-Options",
                    "Không có X-Frame-Options — trang có thể bị nhúng vào iframe của trang độc hại. " +
                            "Attacker dùng kỹ thuật Clickjacking để lừa user click vào element ẩn.",
                    "Thêm: X-Frame-Options: DENY " +
                            "(hoặc SAMEORIGIN nếu cần nhúng iframe trong cùng domain)"
            ),

            new HeaderRule(
                    "x-content-type-options",
                    VulnerabilityType.MISSING_X_CONTENT_TYPE_OPTIONS,
                    Severity.LOW,
                    "Missing X-Content-Type-Options",
                    "Không có X-Content-Type-Options — browser có thể đoán sai MIME type " +
                            "và thực thi file không phải script như script (MIME sniffing attack).",
                    "Thêm: X-Content-Type-Options: nosniff"
            )
    );

    @Override
    public List<Finding> scan(ExecuteResponse response) {
        List<Finding> findings = new ArrayList<>();

        // Normalize về lowercase vì HTTP header case-insensitive
        // "Content-Type" và "content-type" là một
        Map<String, String> headers = normalizeHeaders(response.headers());

        for (HeaderRule rule : RULES) {
            if (!headers.containsKey(rule.headerName())) {
                findings.add(Finding.builder()
                        .vulnerability(rule.vulnerability())
                        .severity(rule.severity())
                        .title(rule.title())
                        .description(rule.description())
                        .recommendation(rule.recommendation())
                        .build());
            }
        }

        // Check riêng vì logic khác — không phải "missing header"
        // mà là "header có nhưng đang lộ thông tin nhạy cảm"
        checkServerVersionDisclosure(headers, findings);

        return findings;
    }

    // Server: nginx/1.18.0 → lộ version → attacker biết CVE nào để tấn công
    // Server: nginx       → an toàn — biết là nginx nhưng không biết version
    private void checkServerVersionDisclosure(
            Map<String, String> headers,
            List<Finding> findings) {

        String serverHeader = headers.get("server");
        if (serverHeader == null) return;

        // Regex: có slash theo sau bởi số → nginx/1.18.0, Apache/2.4.51
        if (serverHeader.matches(".*\\/[0-9].*")) {
            findings.add(Finding.builder()
                    .vulnerability(VulnerabilityType.SERVER_VERSION_DISCLOSURE)
                    .severity(Severity.LOW)
                    .title("Server version disclosure")
                    .description(
                            "Server header đang lộ version: \"" + serverHeader + "\". " +
                                    "Attacker tra cứu CVE database tìm lỗ hổng của version này."
                    )
                    .recommendation(
                            "Config web server chỉ trả tên, bỏ version. " +
                                    "Nginx: server_tokens off; Apache: ServerTokens Prod"
                    )
                    .build());
        }
    }

    // Inner record — gom data của 1 rule lại, thay vì 5 array riêng lẻ
    // Private vì chỉ HeaderScanner dùng, không cần expose ra ngoài
    private record HeaderRule(
            String headerName,
            VulnerabilityType vulnerability,
            Severity severity,
            String title,
            String description,
            String recommendation
    ) {
    }
}

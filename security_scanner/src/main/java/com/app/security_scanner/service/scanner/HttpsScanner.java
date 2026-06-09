package com.app.security_scanner.service.scanner;

import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.enums.Severity;
import com.app.security_scanner.enums.VulnerabilityType;
import com.app.security_scanner.model.Finding;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Slf4j
@Component
public class HttpsScanner extends BaseScanner {

    @Override
    public List<Finding> scan(ExecuteResponse response) {
        // HttpsScanner cần biết URL — không có trong ExecuteResponse
        // → return empty, logic thật ở scanUrl()
        return List.of();
    }

    public List<Finding> scanUrl(String url) {
        List<Finding> findings = new ArrayList<>();

        if (url == null) return findings;

        String urlLower = url.toLowerCase().trim();

        // Check URL dùng HTTP thay vì HTTPS
        if (urlLower.startsWith("http://")) {
            findings.add(Finding.builder()
                    .vulnerability(VulnerabilityType.INSECURE_HTTP)
                    .severity(Severity.HIGH)
                    .title("Insecure HTTP — không dùng HTTPS")
                    .description(
                            "URL đang dùng HTTP: " + url + ". " +
                                    "Toàn bộ data truyền đi plain text — " +
                                    "attacker có thể đọc username, password, token " +
                                    "thông qua Man-in-the-Middle attack."
                    )
                    .recommendation(
                            "Chuyển sang HTTPS. " +
                                    "Dùng Let's Encrypt để có SSL certificate miễn phí: " +
                                    "https://letsencrypt.org"
                    )
                    .build());

            log.warn("Insecure HTTP detected: {}", url);
        }

        return findings;
    }
}
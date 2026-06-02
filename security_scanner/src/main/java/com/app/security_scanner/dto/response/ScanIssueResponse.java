package com.app.security_scanner.dto.response;

import com.app.security_scanner.enums.Severity;
import com.app.security_scanner.enums.VulnerabilityType;

public record ScanIssueResponse(
        VulnerabilityType vulnerability,
        Severity severity,
        String title,
        String description,
        String recommendation
) {
}
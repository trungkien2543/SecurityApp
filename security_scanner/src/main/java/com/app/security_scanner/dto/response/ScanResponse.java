package com.app.security_scanner.dto.response;
import com.app.security_scanner.enums.ScanStatus;

import java.time.LocalDateTime;
import java.util.UUID;
import java.util.List;

public record ScanResponse(

        UUID id,

        String targetUrl,

        String method,

        ScanStatus status,

        Integer responseStatus,

        Long responseTime,

        LocalDateTime createdAt,

        List<ScanIssueResponse> issues

) {
}
package com.app.security_scanner.dto.request;

import jakarta.validation.constraints.NotBlank;

public record CreateScanRequest(

        @NotBlank(message = "Target URL is required")
        String targetUrl,

        @NotBlank(message = "Method is required")
        String method,

        String requestHeaders,

        String requestBody

) {
}
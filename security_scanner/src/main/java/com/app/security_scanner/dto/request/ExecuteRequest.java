package com.app.security_scanner.dto.request;

import jakarta.validation.constraints.NotBlank;

import java.util.Map;

public record ExecuteRequest(

        @NotBlank
        String url,

        @NotBlank
        String method,

        Map<String, String> headers,

        String body
) {
}
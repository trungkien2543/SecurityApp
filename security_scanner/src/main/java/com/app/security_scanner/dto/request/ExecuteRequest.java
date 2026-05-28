package com.app.security_scanner.dto.request;

import java.util.Map;

public record ExecuteRequest(

        String url,
        String method,
        Map<String, String> headers,
        String body

) {
}
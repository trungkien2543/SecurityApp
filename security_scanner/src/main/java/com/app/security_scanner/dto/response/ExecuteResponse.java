package com.app.security_scanner.dto.response;

import java.util.Map;

public record ExecuteResponse(

        int status,
        Map<String, String> headers,
        String body,
        long responseTime

) {
}
package com.app.security_scanner.dto.response;

import org.springframework.http.HttpHeaders;

public record ExecuteResponse(

        int status,

        HttpHeaders headers,

        String body,

        long responseTime

) {
}
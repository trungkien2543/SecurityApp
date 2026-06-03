package com.app.security_scanner.service.scanner;

import org.springframework.http.HttpHeaders;

import java.util.HashMap;
import java.util.Map;

public abstract class BaseScanner implements SecurityScanner {

    protected Map<String, String> normalizeHeaders(HttpHeaders headers) {
        if (headers == null) return Map.of();
        var normalized = new HashMap<String, String>();
        headers.forEach((key, values) -> {
            if (values != null && !values.isEmpty()) {
                normalized.put(key.toLowerCase(), values.get(0));
            }
        });
        return normalized;
    }
}
package com.app.security_scanner.model;

import com.app.security_scanner.enums.Severity;
import com.app.security_scanner.enums.VulnerabilityType;
import lombok.Builder;

@Builder
public record Finding(
        VulnerabilityType vulnerability, // loại lỗ hổng — để FE filter theo category
        Severity severity,               // mức độ — CRITICAL/HIGH/MEDIUM/LOW
        String title,                    // tên ngắn — hiển thị trong list
        String description,             // giải thích chi tiết — tab details
        String recommendation           // cách fix — quan trọng nhất với dev
) {
}
package com.app.security_scanner.entity;

import jakarta.persistence.*;

import lombok.*;

@Entity
@Table(name = "scans")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Scan extends BaseEntity{

    private String targetUrl;

    private String method;

    @Enumerated(EnumType.STRING)
    private ScanStatus status;

    @Column(columnDefinition = "TEXT")
    private String requestHeaders;

    @Column(columnDefinition = "TEXT")
    private String requestBody;

    private Integer responseStatus;

    private Long responseTime;
}
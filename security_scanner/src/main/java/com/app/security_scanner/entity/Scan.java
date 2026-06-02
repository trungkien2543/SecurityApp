package com.app.security_scanner.entity;
import com.app.security_scanner.enums.ScanStatus;
import jakarta.persistence.*;
import lombok.*;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "scans")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class Scan extends BaseEntity {

    private String targetUrl;

    private String method;

    @Enumerated(EnumType.STRING)
    private ScanStatus status;

    @Column(columnDefinition = "TEXT")
    private String requestHeaders;

    @Column(columnDefinition = "TEXT")
    private String requestBody;

    @Column(columnDefinition = "TEXT")
    private String responseBody;

    private Integer responseStatus;

    private Long responseTime;

    @Column(columnDefinition = "TEXT")
    private String errorMessage;      // ← thêm field này

    @OneToMany(
            mappedBy = "scan",
            cascade = CascadeType.ALL,
            orphanRemoval = true
    )
    @Builder.Default
    private List<ScanIssue> issues = new ArrayList<>();
}
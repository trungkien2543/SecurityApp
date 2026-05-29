package com.app.security_scanner.entity;


import com.app.security_scanner.enums.Severity;
import com.app.security_scanner.enums.VulnerabilityType;
import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "scan_issues")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ScanIssue extends BaseEntity {

    @Enumerated(EnumType.STRING)
    private VulnerabilityType vulnerability;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    @Column(columnDefinition = "TEXT")
    private String description;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id")
    private Scan scan;
}
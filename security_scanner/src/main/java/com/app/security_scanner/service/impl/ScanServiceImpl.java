package com.app.security_scanner.service.impl;

import com.app.security_scanner.dto.request.ExecuteRequest;
import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.dto.response.ScanResponse;
import com.app.security_scanner.entity.Scan;
import com.app.security_scanner.entity.ScanIssue;
import com.app.security_scanner.enums.ScanStatus;
import com.app.security_scanner.exception.ResourceNotFoundException;
import com.app.security_scanner.mapper.ScanMapper;
import com.app.security_scanner.repository.ScanRepository;
import com.app.security_scanner.service.RequestExecutorService;
import com.app.security_scanner.service.ScanService;
import com.app.security_scanner.service.SecurityScanService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class ScanServiceImpl implements ScanService {

    private final ScanRepository scanRepository;
    private final RequestExecutorService requestExecutorService;
    private final ScanMapper scanMapper;
    private final SecurityScanService securityScanService;

    @Override
    public ScanResponse scan(
            ExecuteRequest request
    ) {

        Scan scan = Scan.builder()
                .targetUrl(request.url())
                .method(request.method())
                .status(ScanStatus.RUNNING)
                .build();

        scan = scanRepository.save(scan);

        try {
            ExecuteResponse response = requestExecutorService.execute(request);

            scan.setResponseStatus(response.status());
            scan.setResponseTime(response.responseTime());
            scan.setResponseBody(response.body());
            scan.setStatus(ScanStatus.COMPLETED);

            // Security scan chạy sau khi có response
            List<ScanIssue> issues =
                    securityScanService.scanAndBuildIssues(request, response, scan);
            scan.getIssues().addAll(issues);
            // Không cần save issues riêng — CascadeType.ALL tự lo

        } catch (Exception ex) {
            log.error("Scan failed for url={}", request.url(), ex);
            scan.setStatus(ScanStatus.FAILED);
            scan.setErrorMessage(ex.getMessage());
        }

        return scanMapper.toResponse(scanRepository.save(scan));
    }

    @Override
    public ScanResponse getScan(UUID id) {

        Scan scan = scanRepository.findById(id)
                .orElseThrow(() ->
                        new ResourceNotFoundException(
                                "Scan not found"
                        )
                );

        return scanMapper.toResponse(scan);
    }

    @Override
    public Page<ScanResponse> getScans(
            Pageable pageable
    ) {

        return scanRepository.findAll(pageable)
                .map(scanMapper::toResponse);
    }
}
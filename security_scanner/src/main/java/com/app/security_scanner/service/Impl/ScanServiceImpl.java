package com.app.security_scanner.service.Impl;

import com.app.security_scanner.dto.request.CreateScanRequest;
import com.app.security_scanner.dto.response.ScanResponse;
import com.app.security_scanner.entity.Scan;
import com.app.security_scanner.entity.ScanStatus;
import com.app.security_scanner.exception.ResourceNotFoundException;
import com.app.security_scanner.repository.ScanRepository;
import com.app.security_scanner.service.ScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ScanServiceImpl implements ScanService {

    private final ScanRepository scanRepository;

    @Override
    public ScanResponse createScan(CreateScanRequest request) {

        Scan scan = Scan.builder()
                .targetUrl(request.targetUrl())
                .method(request.method())
                .requestHeaders(request.requestHeaders())
                .requestBody(request.requestBody())
                .status(ScanStatus.PENDING)
                .build();

        return mapToResponse(
                scanRepository.save(scan)
        );
    }

    @Override
    public ScanResponse getScan(UUID id) {

        Scan scan = scanRepository.findById(id)
                .orElseThrow(() ->
                new ResourceNotFoundException(
                        "Scan not found"
                )
        );

        return mapToResponse(scan);
    }

    @Override
    public Page<ScanResponse> getScans(Pageable pageable) {

        return scanRepository.findAll(pageable)
                .map(this::mapToResponse);
    }

    private ScanResponse mapToResponse(Scan scan) {

        return new ScanResponse(
                scan.getId(),
                scan.getTargetUrl(),
                scan.getMethod(),
                scan.getStatus(),
                scan.getResponseStatus(),
                scan.getResponseTime(),
                scan.getCreatedAt()
        );
    }
}
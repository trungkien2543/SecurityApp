package com.app.security_scanner.service.impl;

import com.app.security_scanner.dto.request.ExecuteRequest;
import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.dto.response.ScanResponse;
import com.app.security_scanner.entity.Scan;
import com.app.security_scanner.enums.ScanStatus;
import com.app.security_scanner.exception.ResourceNotFoundException;
import com.app.security_scanner.mapper.ScanMapper;
import com.app.security_scanner.repository.ScanRepository;
import com.app.security_scanner.service.RequestExecutorService;
import com.app.security_scanner.service.ScanService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class ScanServiceImpl implements ScanService {

    private final ScanRepository scanRepository;
    private final RequestExecutorService requestExecutorService;
    private final ScanMapper scanMapper;

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

            ExecuteResponse response =
                    requestExecutorService.execute(request);

            scan.setResponseStatus(
                    response.status()
            );

            scan.setResponseTime(
                    response.responseTime()
            );

            scan.setResponseBody(
                    response.body()
            );

            scan.setStatus(
                    ScanStatus.COMPLETED
            );

        } catch (Exception ex) {

            scan.setStatus(
                    ScanStatus.FAILED
            );
        }

        return scanMapper.toResponse(
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
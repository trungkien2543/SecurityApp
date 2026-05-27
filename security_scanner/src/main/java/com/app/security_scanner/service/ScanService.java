package com.app.security_scanner.service;


import com.app.security_scanner.dto.request.CreateScanRequest;
import com.app.security_scanner.dto.response.ScanResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.UUID;

public interface ScanService {

    ScanResponse createScan(CreateScanRequest request);

    ScanResponse getScan(UUID id);

    Page<ScanResponse> getScans(Pageable pageable);
}
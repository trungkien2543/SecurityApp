package com.app.security_scanner.service;


import com.app.security_scanner.dto.response.ScanResponse;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.UUID;
import com.app.security_scanner.dto.request.ExecuteRequest;


public interface ScanService {

    ScanResponse scan(
            ExecuteRequest request
    );

    ScanResponse getScan(
            UUID id
    );

    Page<ScanResponse> getScans(
            Pageable pageable
    );
}
package com.app.security_scanner.service;

import com.app.security_scanner.dto.request.ExecuteRequest;
import com.app.security_scanner.dto.response.ExecuteResponse;

public interface RequestExecutorService {
    ExecuteResponse execute(
            ExecuteRequest request
    );
}

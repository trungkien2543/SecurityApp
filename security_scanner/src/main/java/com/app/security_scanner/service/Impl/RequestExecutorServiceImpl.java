package com.app.security_scanner.service.Impl;

import com.app.security_scanner.dto.request.ExecuteRequest;
import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.service.RequestExecutorService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class RequestExecutorServiceImpl
        implements RequestExecutorService {

    private final WebClient webClient;

    @Override
    public ExecuteResponse execute(
            ExecuteRequest request
    ) {

        long start = System.currentTimeMillis();

        ResponseEntity<String> response = webClient
                .method(
                        HttpMethod.valueOf(
                                request.method()
                                        .toUpperCase()
                        )
                )
                .uri(request.url())
                .headers(headers -> {

                    if (request.headers() != null) {

                        request.headers()
                                .forEach(headers::add);
                    }
                })
                .bodyValue(
                        request.body() != null
                                ? request.body()
                                : ""
                )
                .retrieve()
                .toEntity(String.class)
                .block();

        long end = System.currentTimeMillis();

        Map<String, String> responseHeaders =
                new HashMap<>();

        response.getHeaders()
                .forEach((key, value) -> {

                    responseHeaders.put(
                            key,
                            String.join(",", value)
                    );
                });

        return new ExecuteResponse(
                response.getStatusCode().value(),
                responseHeaders,
                response.getBody(),
                end - start
        );
    }
}
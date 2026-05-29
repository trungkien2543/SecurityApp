package com.app.security_scanner.service.impl;

import com.app.security_scanner.dto.request.ExecuteRequest;
import com.app.security_scanner.dto.response.ExecuteResponse;
import com.app.security_scanner.service.RequestExecutorService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

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

                .exchangeToMono(clientResponse ->
                        clientResponse.toEntity(String.class)
                )

                .block();

        long end = System.currentTimeMillis();

        return new ExecuteResponse(
                response.getStatusCode().value(),
                response.getHeaders(),
                response.getBody(),
                end - start
        );
    }
}
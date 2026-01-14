package com.example.apiversionfuzzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.proxy.http.ProxyRequestHandler;
import burp.api.montoya.proxy.http.ProxyRequestReceivedAction;
import burp.api.montoya.proxy.http.ProxyRequestToBeSentAction;
import burp.api.montoya.proxy.http.InterceptedRequest;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FuzzerProxyHandler implements ProxyRequestHandler {

    private final MontoyaApi api;
    private final FuzzerUI fuzzerUI;
    private final Set<String> testedEndpoints = new HashSet<>();
    // Regex to match /v1, /v2, etc. at the beginning of a segment
    private static final Pattern VERSION_PATTERN = Pattern.compile("/v[0-9]+(?=/|$)");

    public FuzzerProxyHandler(MontoyaApi api, FuzzerUI fuzzerUI) {
        this.api = api;
        this.fuzzerUI = fuzzerUI;
    }

    @Override
    public ProxyRequestReceivedAction handleRequestReceived(InterceptedRequest interceptedRequest) {
        HttpRequest request = interceptedRequest;
        
        if (!api.scope().isInScope(request.url())) {
            return ProxyRequestReceivedAction.continueWith(request);
        }

        String path = request.path();
        Matcher matcher = VERSION_PATTERN.matcher(path);

        if (matcher.find()) {
            String versionString = matcher.group();
            // Normalize path for deduplication: /api/v1/users -> /api/{v}/users
            String normalizedPath = path.replace(versionString, "/{v}");
            String host = request.httpService().host();
            
            // Key for deduplication: Host + Normalized Path
            String key = host + "|" + normalizedPath;

            synchronized (testedEndpoints) {
                if (!testedEndpoints.contains(key)) {
                    testedEndpoints.add(key);
                    // Start fuzzing in a separate thread
                    new Thread(() -> fuzzVersions(request, versionString)).start();
                }
            }
        }

        return ProxyRequestReceivedAction.continueWith(request);
    }

    @Override
    public ProxyRequestToBeSentAction handleRequestToBeSent(InterceptedRequest interceptedRequest) {
        return ProxyRequestToBeSentAction.continueWith(interceptedRequest);
    }

    private void fuzzVersions(HttpRequest originalRequest, String versionString) {
        String[] methods = {"GET", "POST", "PUT", "OPTIONS"};
        String originalPath = originalRequest.path();
        String host = originalRequest.httpService().host();

        // 1. Add the Original Request to the UI first
        // We need to send it or just log it? 
        // The original request is being proxied, so we don't have the response yet in handleRequestReceived.
        // However, we can make a separate request to capture it for our UI, or just log the request and wait for response?
        // Simpler: Just send the original request again (replay) to capture its status for our table, 
        // or we can just log the request details and mark status as "Pending" or 0 if we don't want to replay.
        // But the user wants to "see the first original request".
        // Let's replay it to get the exact response visible in our tool.
        
        try {
            var originalResponse = api.http().sendRequest(originalRequest);
            fuzzerUI.addResult(host, "Original", versionString.replace("/", ""), originalRequest.method(), originalPath, originalResponse.response().statusCode(), originalResponse.response().body().length(), originalRequest, originalResponse.response());
        } catch (Exception e) {
            api.logging().logToError("Error replaying original request: " + e.getMessage());
        }

        // 2. Fuzz other versions
        for (int i = 1; i <= 6; i++) {
            String targetVersion = "v" + i;
            
            // Skip if this is the original version (optional, but usually good to see it compared)
            // If we want to see "Original" separate from "Fuzz", we can skip.
            // But if the user wants to see v1-v6, and original was v1, we might duplicate.
            // Let's skip the exact match of version string if we already logged "Original".
            if (versionString.equals("/" + targetVersion) || versionString.equals("/" + targetVersion + "/")) {
                continue; 
            }
            
            String newPath = originalPath.replace(versionString, "/v" + i);
            
            for (String method : methods) {
                HttpRequest newRequest = originalRequest.withPath(newPath).withMethod(method);
                
                try {
                    var response = api.http().sendRequest(newRequest);
                    fuzzerUI.addResult(host, "Fuzz", targetVersion, method, newPath, response.response().statusCode(), response.response().body().length(), newRequest, response.response());
                } catch (Exception e) {
                    api.logging().logToError("Error sending request: " + e.getMessage());
                }
            }
        }
    }
}

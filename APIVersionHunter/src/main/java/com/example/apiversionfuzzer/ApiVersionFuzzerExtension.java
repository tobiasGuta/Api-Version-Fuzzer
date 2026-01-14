package com.example.apiversionfuzzer;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.UserInterface;

public class ApiVersionFuzzerExtension implements BurpExtension {

    private MontoyaApi api;
    private Logging logging;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.logging = api.logging();

        api.extension().setName("API Version Fuzzer");
        logging.logToOutput("API Version Fuzzer extension loaded.");

        // Initialize UI and Logic here
        FuzzerUI fuzzerUI = new FuzzerUI(api);
        api.userInterface().registerSuiteTab("API Version Fuzzer", fuzzerUI.getUiComponent());
        
        // Register Proxy Handler
        api.proxy().registerRequestHandler(new FuzzerProxyHandler(api, fuzzerUI));
        
        // Register Unload Handler for persistence
        api.extension().registerUnloadingHandler(fuzzerUI::saveState);
    }
}

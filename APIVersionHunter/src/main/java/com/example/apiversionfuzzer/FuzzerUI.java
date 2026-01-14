package com.example.apiversionfuzzer;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class FuzzerUI {

    private final MontoyaApi api;
    private final JPanel mainPanel;
    
    // UI Components
    private final JList<String> hostList;
    private final DefaultListModel<String> hostListModel;
    private final JTable resultTable;
    private final FuzzResultTableModel tableModel;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    
    // Data
    private final Map<String, List<FuzzResult>> dataMap = new HashMap<>();
    private final Gson gson = new Gson();

    public FuzzerUI(MontoyaApi api) {
        this.api = api;
        
        // Setup UI components
        mainPanel = new JPanel(new BorderLayout());
        
        // Initialize Editors first
        requestEditor = api.userInterface().createHttpRequestEditor();
        responseEditor = api.userInterface().createHttpResponseEditor();
        
        // Initialize Table Model first so it can be used in listeners
        tableModel = new FuzzResultTableModel();
        resultTable = new JTable(tableModel);
        resultTable.setAutoCreateRowSorter(true);
        resultTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        // Left Panel: Host List
        hostListModel = new DefaultListModel<>();
        hostList = new JList<>(hostListModel);
        hostList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        
        // Right Click Menu for Host List
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem deleteItem = new JMenuItem("Delete Host");
        deleteItem.addActionListener(e -> {
            String selectedHost = hostList.getSelectedValue();
            if (selectedHost != null) {
                dataMap.remove(selectedHost);
                hostListModel.removeElement(selectedHost);
                tableModel.setResults(new ArrayList<>());
                requestEditor.setRequest(null);
                responseEditor.setResponse(null);
            }
        });
        popupMenu.add(deleteItem);
        
        hostList.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (SwingUtilities.isRightMouseButton(e)) {
                    int index = hostList.locationToIndex(e.getPoint());
                    if (index != -1) {
                        hostList.setSelectedIndex(index);
                        popupMenu.show(hostList, e.getX(), e.getY());
                    }
                }
            }
        });
        
        // Layout
        JSplitPane editorsSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestEditor.uiComponent(), responseEditor.uiComponent());
        editorsSplit.setResizeWeight(0.5);
        
        JSplitPane rightSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, new JScrollPane(resultTable), editorsSplit);
        rightSplit.setResizeWeight(0.5);
        
        JSplitPane mainSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, new JScrollPane(hostList), rightSplit);
        mainSplit.setResizeWeight(0.2);
        
        mainPanel.add(mainSplit, BorderLayout.CENTER);
        
        // Apply Theme
        api.userInterface().applyThemeToComponent(mainPanel);
        api.userInterface().applyThemeToComponent(hostList);
        api.userInterface().applyThemeToComponent(resultTable);
        api.userInterface().applyThemeToComponent(popupMenu);
        
        // Listeners
        hostList.addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                String selectedHost = hostList.getSelectedValue();
                updateTable(selectedHost);
            }
        });
        
        resultTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int selectedRow = resultTable.getSelectedRow();
                if (selectedRow != -1) {
                    // Convert view index to model index in case of sorting
                    int modelRow = resultTable.convertRowIndexToModel(selectedRow);
                    FuzzResult result = tableModel.getResult(modelRow);
                    if (result != null) {
                        if (result.request != null) requestEditor.setRequest(result.request);
                        else requestEditor.setRequest(null);
                        
                        if (result.response != null) responseEditor.setResponse(result.response);
                        else responseEditor.setResponse(null);
                    }
                } else {
                    requestEditor.setRequest(null);
                    responseEditor.setResponse(null);
                }
            }
        });
        
        loadState();
    }

    public Component getUiComponent() {
        return mainPanel;
    }

    public void addResult(String host, String type, String version, String method, String path, int statusCode, int length, HttpRequest request, HttpResponse response) {
        SwingUtilities.invokeLater(() -> {
            List<FuzzResult> results = dataMap.computeIfAbsent(host, k -> new ArrayList<>());
            
            // Deduplication check: Check if this exact result already exists in the list for this host
            // We check method, path, and version.
            boolean exists = results.stream().anyMatch(r -> 
                r.method.equals(method) && 
                r.path.equals(path) && 
                r.version.equals(version)
            );
            
            if (!exists) {
                FuzzResult newResult = new FuzzResult(type, version, method, path, statusCode, length, request, response);
                results.add(newResult);
                
                if (!hostListModel.contains(host)) {
                    hostListModel.addElement(host);
                }
                
                // If this host is currently selected, update the table
                String selectedHost = hostList.getSelectedValue();
                if (host.equals(selectedHost)) {
                    tableModel.addResult(newResult);
                }
            }
        });
    }
    
    private void updateTable(String host) {
        List<FuzzResult> results = dataMap.get(host);
        tableModel.setResults(results);
        requestEditor.setRequest(null);
        responseEditor.setResponse(null);
    }
    
    public void saveState() {
        Map<String, List<FuzzResultData>> dataToSave = new HashMap<>();
        
        for (Map.Entry<String, List<FuzzResult>> entry : dataMap.entrySet()) {
            List<FuzzResultData> list = new ArrayList<>();
            for (FuzzResult r : entry.getValue()) {
                list.add(new FuzzResultData(r));
            }
            dataToSave.put(entry.getKey(), list);
        }
        
        String json = gson.toJson(dataToSave);
        api.persistence().extensionData().setString("fuzzer_data", json);
    }
    
    private void loadState() {
        String json = api.persistence().extensionData().getString("fuzzer_data");
        if (json == null || json.isEmpty()) return;
        
        Type type = new TypeToken<Map<String, List<FuzzResultData>>>(){}.getType();
        Map<String, List<FuzzResultData>> data = gson.fromJson(json, type);
        
        SwingUtilities.invokeLater(() -> {
            dataMap.clear();
            hostListModel.clear();
            
            for (Map.Entry<String, List<FuzzResultData>> entry : data.entrySet()) {
                String host = entry.getKey();
                hostListModel.addElement(host);
                
                List<FuzzResult> results = new ArrayList<>();
                for (FuzzResultData d : entry.getValue()) {
                    HttpService service = HttpService.httpService(d.host, d.port, d.secure);
                    HttpRequest req = HttpRequest.httpRequest(service, d.requestString);
                    HttpResponse res = HttpResponse.httpResponse(d.responseString);
                    results.add(new FuzzResult(d.type, d.version, d.method, d.path, d.statusCode, d.length, req, res));
                }
                dataMap.put(host, results);
            }
            
            if (!hostListModel.isEmpty()) {
                hostList.setSelectedIndex(0);
            }
        });
    }

    // Table Model
    private static class FuzzResultTableModel extends AbstractTableModel {
        private final String[] columnNames = {"Type", "Version", "Method", "Path", "Status", "Length"};
        private List<FuzzResult> results = new ArrayList<>();

        public void setResults(List<FuzzResult> results) {
            this.results = results != null ? results : new ArrayList<>();
            fireTableDataChanged();
        }
        
        public void addResult(FuzzResult result) {
            this.results.add(result);
            fireTableRowsInserted(results.size() - 1, results.size() - 1);
        }
        
        public FuzzResult getResult(int rowIndex) {
            if (rowIndex >= 0 && rowIndex < results.size()) {
                return results.get(rowIndex);
            }
            return null;
        }

        @Override
        public int getRowCount() {
            return results.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            FuzzResult result = results.get(rowIndex);
            switch (columnIndex) {
                case 0: return result.type;
                case 1: return result.version;
                case 2: return result.method;
                case 3: return result.path;
                case 4: return result.statusCode;
                case 5: return result.length;
                default: return null;
            }
        }
        
        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if (columnIndex == 4 || columnIndex == 5) return Integer.class;
            return String.class;
        }
    }

    private static class FuzzResult {
        String type; // Original or Fuzz
        String version;
        String method;
        String path;
        int statusCode;
        int length;
        HttpRequest request;
        HttpResponse response;

        public FuzzResult(String type, String version, String method, String path, int statusCode, int length, HttpRequest request, HttpResponse response) {
            this.type = type;
            this.version = version;
            this.method = method;
            this.path = path;
            this.statusCode = statusCode;
            this.length = length;
            this.request = request;
            this.response = response;
        }
    }
    
    private static class FuzzResultData {
        String type;
        String version;
        String method;
        String path;
        int statusCode;
        int length;
        String requestString;
        String responseString;
        String host;
        int port;
        boolean secure;
        
        public FuzzResultData(FuzzResult result) {
            this.type = result.type;
            this.version = result.version;
            this.method = result.method;
            this.path = result.path;
            this.statusCode = result.statusCode;
            this.length = result.length;
            this.requestString = result.request.toString();
            this.responseString = result.response.toString();
            
            HttpService service = result.request.httpService();
            if (service != null) {
                this.host = service.host();
                this.port = service.port();
                this.secure = service.secure();
            }
        }
    }
}

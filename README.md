# API Version Hunter

**API Version Hunter** is a Burp Suite extension designed to automatically identify and fuzz versioned API endpoints. It helps penetration testers and bug bounty hunters discover undocumented or older API versions (e.g., `v1`, `v2`, `v3`) that may lack security controls present in the current version.

## Features

*   **Automated Detection**: Passive scanning of traffic to identify versioned endpoints (e.g., `/api/v1/user`, `/v2/orders`).
*   **Smart Fuzzing**: Automatically tests versions **v1** through **v6** for every detected endpoint.
*   **Method Permutation**: Fuzzes each version across multiple HTTP methods: `GET`, `POST`, `PUT`, `OPTIONS`.
*   **Scope Aware**: Only acts on traffic defined in your Burp Suite Target Scope to avoid noise.
*   **Clean UI**:
    *   **Master-Detail View**: Organized by Target Host.
    *   **Comparison**: Displays the **Original** request alongside **Fuzzed** results for easy comparison of Status Codes and Content Lengths.
    *   **Sortable Table**: Quickly find interesting 200 OKs or 500 Errors.
    *   **Integrated Editors**: View full Request and Response details within the extension tab.
*   **Deduplication**: Smart logic ensures the same endpoint is not tested multiple times.
*   **State Persistence**: All results are automatically saved within the Burp Project file.
*   **Management**: Right-click on a target host to delete it from the list.

## Installation

1.  Download the latest JAR file from the Releases page.
2.  Open **Burp Suite**.
3.  Navigate to **Extensions** -> **Installed**.
4.  Click **Add**.
5.  Select **Java** as the extension type.
6.  Select the downloaded `APIVersionHunter.jar` file.

## Usage

1.  **Add to Scope**: Ensure your target website is added to the Burp Suite **Target Scope**.
2.  **Browse**: Navigate the application as usual. The extension passively listens for URLs containing version patterns (e.g., `/v1/`).
3.  **View Results**:
    *   Go to the **API Version Hunter** tab.
    *   Select a **Target Host** from the left panel.
    *   Analyze the table on the right. Look for:
        *   **Status Code Differences**: Does `v1` return a 200 OK while `v2` returns 403 Forbidden?
        *   **Length Differences**: Does an older version return more data?
4.  **Manage**: Right-click a host in the left panel to remove it if needed.

<img width="1909" height="997" alt="Screenshot 2026-01-14 175426" src="https://github.com/user-attachments/assets/416e31b1-783a-40ad-9096-2ab7f73b1669" />

## Building from Source

Requirements:
*   JDK 17 or higher
*   Gradle

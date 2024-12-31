migth fuck up your system im still workin on it, its nowhere close to being done






















































#include <windows.h>
#include <array>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <stdexcept>
#include <codecvt>
#include <cstdio>
#include <sstream>
#include <unordered_map>
#include <fstream>
#include <iomanip>
#include <chrono>
#include <objbase.h>
#include <mutex>
#include <regex>

std::mutex backupMutex;

// Utility for logging with timestamps
void logMessage(const std::string& message, bool isError = false) {
    auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::string timeStr = std::ctime(&now);
    timeStr.pop_back(); // Remove trailing newline

    if (isError) {
        std::cerr << "[" << timeStr << "] [-] Error: " << message << std::endl;
    }
    else {
        std::cout << "[" << timeStr << "] [+] " << message << std::endl;
    }
}

// Generate a valid random MAC address
std::string generateRandomMAC() {
    std::ostringstream mac;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (int i = 0; i < 6; ++i) {
        if (i > 0) mac << ":";
        mac << std::hex << std::setw(2) << std::setfill('0') << (dis(gen) & 0xFF);
    }
    return mac.str();
}

// Generate a random alphanumeric string of specified length
std::string generateRandomString(size_t length) {
    const std::string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    std::random_device rd;
    std::mt19937 generator(rd());
    std::uniform_int_distribution<> distribution(0, chars.size() - 1);

    std::string result;
    result.reserve(length);
    for (size_t i = 0; i < length; ++i) {
        result += chars[distribution(generator)];
    }

    return result;
}

// Securely clear sensitive data
void secureClear(std::string& data) {
    volatile char* p = const_cast<char*>(data.data());
    for (size_t i = 0; i < data.size(); ++i) {
        p[i] = 0;
    }
    data.clear();
}

// Generate a new GUID
std::string generateGUID() {
    GUID guid;
    if (FAILED(CoCreateGuid(&guid))) {
        throw std::runtime_error("Failed to create GUID");
    }

    std::ostringstream oss;
    oss << std::uppercase << std::hex << std::setfill('0')
        << "{" << std::setw(8) << guid.Data1 << "-"
        << std::setw(4) << guid.Data2 << "-"
        << std::setw(4) << guid.Data3 << "-"
        << std::setw(2) << static_cast<int>(guid.Data4[0])
        << std::setw(2) << static_cast<int>(guid.Data4[1]) << "-"
        << std::setw(2) << static_cast<int>(guid.Data4[2])
        << std::setw(2) << static_cast<int>(guid.Data4[3])
        << std::setw(2) << static_cast<int>(guid.Data4[4])
        << std::setw(2) << static_cast<int>(guid.Data4[5])
        << std::setw(2) << static_cast<int>(guid.Data4[6])
        << std::setw(2) << static_cast<int>(guid.Data4[7]) << "}";

    return oss.str();
}

// Validate registry key format
bool isValidRegistryPath(const std::string& path) {
    const std::regex pattern(R"(^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\.+)");
    return std::regex_match(path, pattern);
}

// Backup to file
void saveBackupsToFile(const std::unordered_map<std::string, std::string>& backups, const std::string& filename) {
    std::lock_guard<std::mutex> lock(backupMutex);
    std::ofstream backupFile(filename, std::ios::out | std::ios::trunc);
    if (!backupFile.is_open()) {
        throw std::runtime_error("Failed to open backup.");
    }

    for (const auto& [key, value] : backups) {
        backupFile << key << "=" << value << "\n";
    }

    backupFile.close();
    logMessage("Backups saved at " + filename);
}

// Helper function to set a registry value with backup
bool setRegistryValueWithBackup(HKEY hKeyRoot, const std::string& subKey, const std::string& valueName, const std::string& newValue, std::unordered_map<std::string, std::string>& backups) {
    if (newValue.empty()) {
        logMessage("New registry value cannot be empty.", true);
        return false;
    }

    HKEY hKey = nullptr;
    DWORD dataSize = 0;
    char oldValue[512] = { 0 };

    LONG result = RegOpenKeyExA(hKeyRoot, subKey.c_str(), 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &hKey);
    if (result != ERROR_SUCCESS) {
        logMessage("Failed to open registry key: " + subKey + ". Error code: " + std::to_string(result), true);
        return false;
    }

    try {
        result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, nullptr, reinterpret_cast<LPBYTE>(oldValue), &dataSize);
        if (result == ERROR_SUCCESS) {
            std::lock_guard<std::mutex> lock(backupMutex);
            backups[subKey + "\\" + valueName] = std::string(oldValue, dataSize);
        }
        else if (result != ERROR_FILE_NOT_FOUND) {
            logMessage("Failed to read registry value: " + valueName + " under " + subKey + ". Error code: " + std::to_string(result), true);
        }

        result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(newValue.c_str()), static_cast<DWORD>(newValue.size() + 1));
        if (result != ERROR_SUCCESS) {
            logMessage("Failed to set registry value: " + valueName + " under " + subKey + ". Error code: " + std::to_string(result), true);
            throw std::runtime_error("Registry modification failed");
        }

        logMessage("Set registry value: " + valueName + " to " + newValue);
    }
    catch (const std::exception& ex) {
        logMessage(std::string("Exception occurred: ") + ex.what(), true);
        RegCloseKey(hKey);
        return false;
    }

    RegCloseKey(hKey);
    return true;
}

// Restore a registry value from backup with enhanced validation and error handling
void restoreRegistryValues(const std::unordered_map<std::string, std::string>& backups) {
    logMessage("An Error occured, attempting to restore everything...");

    size_t totalEntries = backups.size();
    size_t restoredEntries = 0;
    size_t failedEntries = 0;

    for (const auto& [key, value] : backups) {
        size_t pos = key.find_last_of('\\');
        if (pos == std::string::npos) {
            logMessage("Invalid backup format: " + key, true);
            failedEntries++;
            continue;
        }

        std::string subKey = key.substr(0, pos);
        std::string valueName = key.substr(pos + 1);

        HKEY hKey = nullptr;
        LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_SET_VALUE, &hKey);
        if (result != ERROR_SUCCESS) {
            logMessage("Failed to open registry key: " + subKey + " Error code: " + std::to_string(result), true);
            failedEntries++;
            continue;
        }

        result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()), static_cast<DWORD>(value.size() + 1));
        if (result == ERROR_SUCCESS) {
            logMessage("Registry restored with value: " + valueName + " under " + subKey);
            restoredEntries++;
        }
        else {
            logMessage("Failed to restore registry value: " + valueName + " under " + subKey + ". Error code: " + std::to_string(result), true);
            failedEntries++;
        }

        RegCloseKey(hKey);
    }

    logMessage("Sucessfully restored. Total entries: " + std::to_string(totalEntries) +
        ", Restored: " + std::to_string(restoredEntries) +
        ", Failed: " + std::to_string(failedEntries));

    if (failedEntries > 0) {
        logMessage("Something went wrong. Check the backup file and try to restore it manually.", true);
    }
}

// Function to spoof InstallationID
void spoofInstallationID(std::unordered_map<std::string, std::string>& backups) {
    try {
        std::string newID = generateGUID();
        if (!setRegistryValueWithBackup(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "InstallationID", newID, backups)) {
            throw std::runtime_error("Failed to change the InstallationID");
        }
        logMessage("Changed InstallationID to: " + newID);
    }
    catch (const std::exception& ex) {
        logMessage(ex.what(), true);
        restoreRegistryValues(backups);
    }
}

// Function to spoof the computer name
void spoofComputerName(std::unordered_map<std::string, std::string>& backups) {
    try {
        std::string newName = generateRandomString(8);

        bool success = setRegistryValueWithBackup(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName", "ComputerName", newName, backups) &&
            setRegistryValueWithBackup(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ActiveComputerName", "ComputerName", newName, backups) &&
            setRegistryValueWithBackup(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters", "Hostname", newName, backups);

        if (!success) {
            throw std::runtime_error("Failed to change the Computer Name");
        }
        logMessage("Chaged Computer Name to : " + newName);
    }
    catch (const std::exception& ex) {
        logMessage(ex.what(), true);
        restoreRegistryValues(backups);
    }
}

// Function to spoof Machine GUID
void spoofGUIDs(std::unordered_map<std::string, std::string>& backups) {
    try {
        std::string newGUID = generateGUID();
        if (!setRegistryValueWithBackup(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", "MachineGuid", newGUID, backups)) {
            throw std::runtime_error("Failed to change the Machine GUID");
        }
        logMessage("Changed Machine GUID to: " + newGUID);
    }
    catch (const std::exception& ex) {
        logMessage(ex.what(), true);
        restoreRegistryValues(backups);
    }
}

// Function to spoof BIOS Serial Number
void spoofBIOS(std::unordered_map<std::string, std::string>& backups) {
    try {
        std::string newBIOS = generateRandomString(16); // Random BIOS serial
        if (!setRegistryValueWithBackup(HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System", "SystemBiosVersion", newBIOS, backups)) {
            throw std::runtime_error("Failed to change the BIOS Serial Number");
        }
        logMessage("Changed BIOS Serial Number to: " + newBIOS);
    }
    catch (const std::exception& ex) {
        logMessage(ex.what(), true);
        restoreRegistryValues(backups);
    }
}

// Function to spoof Disk Drive Serial Number
void spoofDiskSerial(std::unordered_map<std::string, std::string>& backups) {
    try {
        std::string newSerial = generateRandomString(12); // Random Disk Serial
        if (!setRegistryValueWithBackup(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services\\disk", "SerialNumber", newSerial, backups)) {
            throw std::runtime_error("Failed to change the Disk Serial Number");
        }
        logMessage("Changed Disk Serial Number to: " + newSerial);
    }
    catch (const std::exception& ex) {
        logMessage(ex.what(), true);
        restoreRegistryValues(backups);
    }
}

// Function to spoof MAC Address
void spoofMACAddress(std::unordered_map<std::string, std::string>& backups) {
    try {
        std::string newMAC = generateRandomString(12); // Random MAC address-like value
        if (!setRegistryValueWithBackup(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}\\0001", "NetworkAddress", newMAC, backups)) {
            throw std::runtime_error("Failed to change the MAC Address");
        }
        logMessage("Changed MAC Address to: " + newMAC);
    }
    catch (const std::exception& ex) {
        logMessage(ex.what(), true);
        restoreRegistryValues(backups);
    }
}

// Main function to run all spoofers
int main() {
    std::unordered_map<std::string, std::string> backups;
    const std::string backupFile = "backup.txt";

    std::cout << "HWID Spoofer - V1" << std::endl;

    try {
        spoofInstallationID(backups);
        spoofComputerName(backups);
        spoofGUIDs(backups);
        spoofBIOS(backups);
        spoofDiskSerial(backups);
        spoofMACAddress(backups);

        saveBackupsToFile(backups, backupFile);

        std::cout << "IT migth have been sucessful, pray and restart your device." << std::endl;
    }
    catch (const std::exception& ex) {
        logMessage(std::string("Critical error: ") + ex.what(), true);
        restoreRegistryValues(backups);
    }

    return 0;
}

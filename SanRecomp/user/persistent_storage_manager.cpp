#include "persistent_storage_manager.h"
#include "paths.h"
#include <os/logger.h>

std::filesystem::path PersistentStorageManager::GetDataPath(bool extended)
{
    auto basePath = GetUserPath();
    
    if (extended)
        return basePath / "persistent_ext.bin";
    else
        return basePath / "persistent.bin";
}

std::filesystem::path PersistentStorageManager::GetGTA5SavePath(int slot)
{
    auto savePath = GetSavePath(false);
    std::error_code ec;
    std::filesystem::create_directories(savePath, ec);
    
    char filename[64];
    snprintf(filename, sizeof(filename), "SGTA5%03d", slot);
    return savePath / filename;
}

bool PersistentStorageManager::LoadBinary()
{
    BinStatus = EExtBinStatus::Success;
    
    auto dataPath = GetDataPath(true);
    
    if (!std::filesystem::exists(dataPath))
    {
        dataPath = GetDataPath(false);
        
        if (!std::filesystem::exists(dataPath))
            return true; // No data yet, that's fine
    }
    
    std::error_code ec;
    auto fileSize = std::filesystem::file_size(dataPath, ec);
    auto dataSize = sizeof(PersistentData);
    
    if (fileSize != dataSize)
    {
        BinStatus = EExtBinStatus::BadFileSize;
        return false;
    }
    
    std::ifstream file(dataPath, std::ios::binary);
    
    if (!file)
    {
        BinStatus = EExtBinStatus::IOError;
        return false;
    }
    
    PersistentData data{};
    
    file.read(reinterpret_cast<char*>(&data.Signature), sizeof(data.Signature));
    
    if (!data.VerifySignature())
    {
        BinStatus = EExtBinStatus::BadSignature;
        file.close();
        return false;
    }
    
    file.read(reinterpret_cast<char*>(&data.Version), sizeof(data.Version));
    
    if (!data.VerifyVersion())
    {
        BinStatus = EExtBinStatus::BadVersion;
        file.close();
        return false;
    }
    
    file.seekg(0);
    file.read(reinterpret_cast<char*>(&data), sizeof(data));
    file.close();
    
    memcpy(&Data, &data, dataSize);
    
    return true;
}

bool PersistentStorageManager::SaveBinary()
{
    LOGN("Saving persistent storage binary...");
    
    auto dataPath = GetDataPath(true);
    
    // Ensure directory exists
    std::error_code ec;
    std::filesystem::create_directories(dataPath.parent_path(), ec);
    
    std::ofstream file(dataPath, std::ios::binary);
    
    if (!file)
    {
        LOGN_ERROR("Failed to write persistent storage binary.");
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(&Data), sizeof(PersistentData));
    file.close();
    
    BinStatus = EExtBinStatus::Success;
    
    return true;
}

bool PersistentStorageManager::LoadGTA5Save(int slot, void* buffer, size_t size)
{
    auto savePath = GetGTA5SavePath(slot);
    
    if (!std::filesystem::exists(savePath))
        return false;
    
    std::ifstream file(savePath, std::ios::binary);
    
    if (!file)
        return false;
    
    file.read(reinterpret_cast<char*>(buffer), size);
    auto bytesRead = file.gcount();
    file.close();
    
    LOGFN("Loaded GTA V save slot {} ({} bytes)", slot, bytesRead);
    
    return bytesRead > 0;
}

bool PersistentStorageManager::SaveGTA5Save(int slot, const void* buffer, size_t size)
{
    auto savePath = GetGTA5SavePath(slot);
    
    // Ensure directory exists
    std::error_code ec;
    std::filesystem::create_directories(savePath.parent_path(), ec);
    
    std::ofstream file(savePath, std::ios::binary);
    
    if (!file)
    {
        LOGFN_ERROR("Failed to save GTA V slot {}", slot);
        return false;
    }
    
    file.write(reinterpret_cast<const char*>(buffer), size);
    file.close();
    
    LOGFN("Saved GTA V slot {} ({} bytes)", slot, size);
    
    return true;
}

bool PersistentStorageManager::DeleteGTA5Save(int slot)
{
    auto savePath = GetGTA5SavePath(slot);
    
    std::error_code ec;
    if (std::filesystem::remove(savePath, ec))
    {
        LOGFN("Deleted GTA V save slot {}", slot);
        return true;
    }
    
    return false;
}

bool PersistentStorageManager::GTA5SaveExists(int slot)
{
    return std::filesystem::exists(GetGTA5SavePath(slot));
}

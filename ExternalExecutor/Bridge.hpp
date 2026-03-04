#pragma once
#define CPPHTTPLIB_OPENSSL_SUPPORT
#include "Dependecies/server/httplib.h"
using namespace httplib;

#include "Dependecies/server/nlohmann/json.hpp"
using json = nlohmann::json;

#include <regex>
#include <filesystem>
#include <fstream>

#include "Utils/Process.hpp"
#include "Utils/Instance.hpp"
#include "Utils/Bytecode.hpp"
#include "Dependecies/lz4/include/lz4.h"

#include <openssl/sha.h>
// for getscripthash
std::string SHA384Hex(const uint8_t* data, size_t size)
{
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA384(data, size, hash);

    std::stringstream ss;
    for (int i = 0; i < SHA384_DIGEST_LENGTH; i++)
        ss << std::hex
           << std::setw(2)
           << std::setfill('0')
           << (int)hash[i];

    return ss.str();
}

inline std::string script = "";
inline uintptr_t order = 0;
inline std::unordered_map<DWORD, uintptr_t> orders;

inline std::vector<std::string> SplitLines(const std::string& str) {
	std::stringstream ss(str);
	std::string line;
	std::vector<std::string> lines;
	while (std::getline(ss, line, '\n'))
		lines.push_back(line);
	return lines;
}

inline Instance GetPointerInstance(std::string name, DWORD ProcessID) {
	uintptr_t Base = Process::GetModuleBase(ProcessID);
	Instance Datamodel = FetchDatamodel(Base, ProcessID);
	Instance CoreGui = Datamodel.FindFirstChild("CoreGui");
	Instance ExternalExecutor = CoreGui.FindFirstChild("ExternalExecutor");
	Instance Pointers = ExternalExecutor.FindFirstChild("Pointer");
	Instance Pointer = Pointers.FindFirstChild(name);
	uintptr_t Target = ReadMemory<uintptr_t>(Pointer.GetAddress() + Offsets::Value, ProcessID);
	return Instance(Target, ProcessID);
}

inline std::string GetWorkspaceDirectory() {
	char* appdata = nullptr;
	size_t len = 0;
	if (_dupenv_s(&appdata, &len, "LOCALAPPDATA") == 0 && appdata) {
		std::string path = std::string(appdata) + "\\ExternalExecutor\\workspace\\";
		free(appdata);
		std::filesystem::create_directories(path);
		return path;
	}
	return ".\\workspace\\";
}

inline std::string ReadStdString(uintptr_t strAddr, DWORD pid)
{
    if (!strAddr)
        return "";

    size_t size = ReadMemory<size_t>(strAddr + 0x10, pid);

    if (size == 0 || size > 10 * 1024 * 1024)
        return "";

    uintptr_t dataAddr;

    if (size >= 16)
        dataAddr = ReadMemory<uintptr_t>(strAddr, pid);
    else
        dataAddr = strAddr;

    if (!dataAddr)
        return "";

    std::vector<char> buffer(size);
    Memory::ReadNative(dataAddr, buffer.data(), size, pid);

    return std::string(buffer.data(), size);
}

inline std::unordered_map<std::string, std::function<std::string(std::string, nlohmann::json, DWORD)>> env;
inline void Load() {
	env["listen"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		std::string res;
		if (orders.contains(pid)) {
			if (orders[pid] < order) {
				res = script;
			}
			else {
				res = "";
			}
			orders[pid] = order;
		}
		else {
			orders[pid] = order;
			res = script;
		}
		return res;
		};
	env["compile"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		if (set["enc"] == "true") {
			return Bytecode::Compile(dta);
		}
		return Bytecode::NormalCompile(dta);
		};
	env["setscriptbytecode"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		size_t Sized;
		auto Compressed = Bytecode::Sign(dta, Sized);

		Instance TheScript = GetPointerInstance(set["cn"], pid);
		TheScript.SetScriptBytecode(Compressed, Sized);

		return "";
		};
	env["request"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		std::string url = set["l"];
		std::string method = set["m"];
		std::string rBody = set["b"];
		json headersJ = set["h"];

		std::regex urlR(R"(^(http[s]?:\/\/)?([^\/]+)(\/.*)?$)");
		std::smatch urlM;
		std::string host;
		std::string path = "/";

		if (std::regex_match(url, urlM, urlR)) {
			host = urlM[2];
			if (urlM[3].matched) path = urlM[3];
		}
		else {
			return std::string("[]");
		}

		Client client(host.c_str());
		client.set_follow_location(true);

		Headers headers;
		for (auto it = headersJ.begin(); it != headersJ.end(); ++it) {
			headers.insert({ it.key(), it.value() });
		}

		Result proxiedRes;
		if (method == "GET") {
			proxiedRes = client.Get(path, headers);
		}
		else if (method == "POST") {
			proxiedRes = client.Post(path, headers, rBody, "application/json");
		}
		else if (method == "PUT") {
			proxiedRes = client.Put(path, headers, rBody, "application/json");
		}
		else if (method == "DELETE") {
			proxiedRes = client.Delete(path, headers, rBody, "application/json");
		}
		else if (method == "PATCH") {
			proxiedRes = client.Patch(path, headers, rBody, "application/json");
		}
		else {
			return std::string("[]");
		}

		if (proxiedRes) {
			json responseJ;
			responseJ["b"] = proxiedRes->body;
			responseJ["c"] = proxiedRes->status;
			responseJ["r"] = proxiedRes->reason;
			responseJ["v"] = proxiedRes->version;

			json rHeadersJ;
			for (const auto& header : proxiedRes->headers) {
				rHeadersJ[header.first] = header.second;
			}
			responseJ["h"] = rHeadersJ;

			return responseJ.dump();
		}
		return std::string("[]");
		};

	env["writefile"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			std::string filepath = GetWorkspaceDirectory() + std::string(set["path"]);
			std::filesystem::path fpath(filepath);
			std::filesystem::create_directories(fpath.parent_path());
			std::ofstream file(filepath, std::ios::binary);
			if (file.is_open()) {
				file.write(dta.c_str(), dta.size());
				file.close();
				return "true";
			}
		}
		catch (...) {}
		return "false";
		};

	env["readfile"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			std::string filepath = GetWorkspaceDirectory() + std::string(set["path"]);
			if (!std::filesystem::exists(filepath)) {
				return std::string("[ERROR] File does not exist");
			}
			std::ifstream file(filepath, std::ios::binary | std::ios::ate);
			if (file.is_open()) {
				std::streamsize size = file.tellg();
				file.seekg(0);
				std::string buffer(size, '\0');
				file.read(&buffer[0], size);
				file.close();
				return buffer;
			}
		}
		catch (...) {}
		return std::string("[ERROR] Failed to read file");
		};

	env["appendfile"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			std::string filepath = GetWorkspaceDirectory() + std::string(set["path"]);
			std::filesystem::path fpath(filepath);
			std::filesystem::create_directories(fpath.parent_path());
			std::ofstream file(filepath, std::ios::binary | std::ios::app);
			if (file.is_open()) {
				file.write(dta.c_str(), dta.size());
				file.close();
				return "true";
			}
		}
		catch (...) {}
		return "false";
		};

	env["isfile"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			std::string filepath = GetWorkspaceDirectory() + std::string(set["path"]);
			return std::filesystem::is_regular_file(filepath) ? "true" : "false";
		}
		catch (...) {}
		return "false";
		};

	env["isfolder"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			std::string filepath = GetWorkspaceDirectory() + std::string(set["path"]);
			return std::filesystem::is_directory(filepath) ? "true" : "false";
		}
		catch (...) {}
		return "false";
		};

	env["makefolder"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			std::string filepath = GetWorkspaceDirectory() + std::string(set["path"]);
			std::filesystem::create_directories(filepath);
			return "true";
		}
		catch (...) {}
		return "false";
		};

	env["listfiles"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			std::string folderpath = GetWorkspaceDirectory() + std::string(set["path"]);
			if (!std::filesystem::is_directory(folderpath)) {
				return std::string("[]");
			}
			json fileList = json::array();
			std::string workspaceDir = GetWorkspaceDirectory();
			for (const auto& entry : std::filesystem::directory_iterator(folderpath)) {
				std::string fullPath = entry.path().string();
				std::string relativePath = fullPath.substr(workspaceDir.length());
				std::replace(relativePath.begin(), relativePath.end(), '\\', '/');
				fileList.push_back(relativePath);
			}
			return fileList.dump();
		}
		catch (...) {}
		return std::string("[]");
		};

	env["delfile"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			std::string filepath = GetWorkspaceDirectory() + std::string(set["path"]);
			if (std::filesystem::remove(filepath)) {
				return "true";
			}
		}
		catch (...) {}
		return "false";
		};

	env["delfolder"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			std::string filepath = GetWorkspaceDirectory() + std::string(set["path"]);
			std::filesystem::remove_all(filepath);
			return "true";
		}
		catch (...) {}
		return "false";
		};

	env["getcustomasset"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			std::string filepath = set["path"];
			std::string workspacePath = GetWorkspaceDirectory();
			std::string fullPath = workspacePath + filepath;
			
			if (!std::filesystem::exists(fullPath)) {
				return std::string("");
			}
			
			char* appdata = nullptr;
			size_t len = 0;
			if (_dupenv_s(&appdata, &len, "LOCALAPPDATA") != 0 || !appdata) {
				return std::string("");
			}
			
			std::string robloxPath = std::string(appdata) + "\\Roblox\\Versions";
			free(appdata);
			
			std::string versionPath;
			for (const auto& entry : std::filesystem::directory_iterator(robloxPath)) {
				if (entry.is_directory() && entry.path().filename().string().find("version-") != std::string::npos) {
					versionPath = entry.path().string();
					break;
				}
			}
			
			if (versionPath.empty()) {
				return std::string("");
			}
			
			std::string contentPath = versionPath + "\\content\\ExternalExecutor\\";
			std::filesystem::create_directories(contentPath);
			
			GUID guid;
			CoCreateGuid(&guid);
			char guid_str[40];
			sprintf_s(guid_str, "%08X%04X%04X%02X%02X%02X%02X%02X%02X%02X%02X",
				guid.Data1, guid.Data2, guid.Data3,
				guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
				guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
			
			std::string extension = fullPath.substr(fullPath.find_last_of('.'));
			std::string fileName = std::string(guid_str) + extension;
			std::string destPath = contentPath + fileName;
			
			std::filesystem::copy_file(fullPath, destPath, std::filesystem::copy_options::overwrite_existing);
			
			return "rbxasset://ExternalExecutor/" + fileName;
		}
		catch (...) {}
		return std::string("");
		};

	env["setclipboard"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			if (!OpenClipboard(nullptr)) {
				return std::string("false");
			}
			
			EmptyClipboard();
			
			HGLOBAL hGlobal = GlobalAlloc(GMEM_MOVEABLE, dta.size() + 1);
			if (!hGlobal) {
				CloseClipboard();
				return std::string("false");
			}
			
			void* pGlobal = GlobalLock(hGlobal);
			if (!pGlobal) {
				GlobalFree(hGlobal);
				CloseClipboard();
				return std::string("false");
			}
			
			memcpy(pGlobal, dta.c_str(), dta.size() + 1);
			GlobalUnlock(hGlobal);
			
			if (!SetClipboardData(CF_TEXT, hGlobal)) {
				GlobalFree(hGlobal);
				CloseClipboard();
				return std::string("false");
			}
			
			CloseClipboard();
			return std::string("true");
		}
		catch (...) {}
		return std::string("false");
		};

	env["lz4compress"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			int maxCompressedSize = LZ4_compressBound(static_cast<int>(dta.size()));
			std::vector<char> compressed(maxCompressedSize);
			
			int compressedSize = LZ4_compress_default(
				dta.c_str(), 
				compressed.data(), 
				static_cast<int>(dta.size()), 
				maxCompressedSize
			);
			
			if (compressedSize <= 0) {
				return std::string("");
			}
			
			return std::string(compressed.data(), compressedSize);
		}
		catch (...) {}
		return std::string("");
		};

	env["lz4decompress"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			size_t originalSize = std::stoull(std::string(set["originalSize"]));
			std::vector<char> decompressed(originalSize);
			
			int decompressedSize = LZ4_decompress_safe(
				dta.c_str(),
				decompressed.data(),
				static_cast<int>(dta.size()),
				static_cast<int>(originalSize)
			);
			
			if (decompressedSize < 0) {
				return std::string("");
			}
			
			return std::string(decompressed.data(), decompressedSize);
		}
		catch (...) {}
		return std::string("");
		};

	env["getscriptbytecode"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			Instance script = GetPointerInstance(set["cn"], pid);
			return std::string("");
		}
		catch (...) {}
		return std::string("");
		};

	env["getinstanceaddr"] = [](std::string dta, nlohmann::json set, DWORD pid) {
		try {
			Instance script = GetPointerInstance(set["name"], pid);
			return std::to_string(script.GetAddress());
		}
		catch (...) {}
		return std::string("0");
		};

	env["getscripthash"] = [](std::string dta, nlohmann::json set, DWORD pid) -> std::string
{
    try
    {
        Instance script = GetPointerInstance(set["cn"], pid);
        uintptr_t scriptAddr = script.GetAddress();
        if (!scriptAddr)
            return "";

        uintptr_t classDescriptor = ReadMemory<uintptr_t>(scriptAddr + Offsets::ClassDescriptor, pid);
        if (!classDescriptor)
            return "";

        uintptr_t classNamePtr = ReadMemory<uintptr_t>(classDescriptor + Offsets::ClassDescriptorToClassName, pid);
        if (!classNamePtr)
            return "";

        std::string className = ReadStdString(classNamePtr, pid);
        if (className.empty())
            return "";

        uintptr_t bytecodeOffset = 0;
        if (className == "LocalScript")
            bytecodeOffset = Offsets::LocalScriptByteCode;
        else if (className == "ModuleScript")
            bytecodeOffset = Offsets::ModuleScriptByteCode;
        else if (className == "Script")
            bytecodeOffset = Offsets::LocalScriptByteCode;
        else
            return "";

        uintptr_t embeddedPtr = ReadMemory<uintptr_t>(scriptAddr + bytecodeOffset, pid);
        if (!embeddedPtr)
            return "";

        std::string compressed = ReadStdString(embeddedPtr + 0x10, pid);
        if (compressed.empty())
            return ""; // Lua will convert "" → nil

        return SHA384Hex(reinterpret_cast<const uint8_t*>(compressed.data()), compressed.size());
    }
    catch (...)
    {
        return "";
    }
	};
}

inline std::string Setup(std::string args) {
	auto lines = SplitLines(args);

	std::string typ = lines.size() > 0 ? lines[0] : "";
	DWORD pid = lines.size() > 1 ? std::stoul(lines[1]) : 0;
	nlohmann::json set = lines.size() > 2 ? nlohmann::json::parse(lines[2]) : nlohmann::json{};
	std::string dta;

	for (size_t i = 3; i < lines.size(); ++i) {
		dta += lines[i];
		if (i + 1 < lines.size()) dta += "\n";
	}

	return env[typ] ? env[typ](dta, set, pid) : "";
}

inline void StartBridge()
{
	Load();
	Server Bridge;
	Bridge.Post("/handle", [](const Request& req, Response& res) {
		res.status = 200;
		res.set_content(Setup(req.body), "text/plain");
		});
	Bridge.set_exception_handler([](const Request& req, Response& res, std::exception_ptr ep) {
		std::string errorMessage;
		try {
			std::rethrow_exception(ep);
		}
		catch (std::exception& e) {
			errorMessage = e.what();
		}
		catch (...) {
			errorMessage = "Unknown Exception";
		}
		res.set_content("{\"error\":\"" + errorMessage + "\"}", "application/json");
		res.status = 500;
		});
	Bridge.listen("localhost", 9611);
}

inline void Execute(std::string source) {
	script = source;
	order += 1;
}
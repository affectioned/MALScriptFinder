using System;
using System.IO;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using UnityEngine;

public static class AssetValidator
{
    private static readonly string[] suspiciousKeywords = {
        "UnityWebRequest", "WWW", "HttpClient", "WebClient", "Socket", "TcpClient", "TcpListener", "UdpClient", "Network"
    };

    private static readonly string[] dangerousFileExtensions = {
        ".dll", ".exe", ".zip", ".rar", ".tar", ".7z", ".gz", ".bz2"
    };

    private static readonly string[] whiteList = {
        "AssetValidator", "AssetScanner", "signtool"
    };

    public static bool IsAssetMalicious(string assetPath)
    {
        string fileName = Path.GetFileNameWithoutExtension(assetPath);
        if (Array.Exists(whiteList, file => fileName.Contains(file)))
        {
            return false;
        }

        // Check for dangerous file extensions
        foreach (string extension in dangerousFileExtensions)
        {
            if (assetPath.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
            {
                if (extension == ".dll")
                {
                    if (!IsDllSigned(assetPath))
                    {
                        Debug.LogError($"{fileName} DLL is not valid signed. {assetPath}");
                        return true; // Flag unsigned DLLs as malicious
                    }
                    continue;
                }
                return true;
            }
        }

        // Check for suspicious keywords in script files
        if (assetPath.EndsWith(".cs", StringComparison.OrdinalIgnoreCase))
        {
            string scriptContent = File.ReadAllText(assetPath);
            foreach (string keyword in suspiciousKeywords)
            {
                if (Regex.IsMatch(scriptContent, @"\b" + Regex.Escape(keyword) + @"\b", RegexOptions.IgnoreCase))
                {
                    return true;
                }
            }
        }

        return false;
    }

     public static bool IsDllSigned(string dllPath)
    {
        try
        {
            if (!File.Exists(dllPath))
            {
                Debug.LogError("DLL file not found: " + dllPath);
                return false;
            }

            // Locate the AssetValidator.cs file to determine script directory
            string[] res = Directory.GetFiles(Application.dataPath, "AssetValidator.cs", SearchOption.AllDirectories);
            if (res.Length == 0)
            {
                Debug.LogError("AssetValidator.cs not found! Ensure it is inside the Unity project.");
                return false;
            }

            // Get the directory of AssetValidator.cs and replace backslashes for compatibility
            string scriptDirectory = res[0].Replace("AssetValidator.cs", "").Replace("\\", "/");
            string signtoolPath = Path.Combine(scriptDirectory, "signtool.exe").Replace("\\", "/");

            if (!File.Exists(signtoolPath))
            {
                Debug.LogError($"signtool.exe not found at: {signtoolPath}");
                return false;
            }

            System.Diagnostics.Process process = new System.Diagnostics.Process();
            process.StartInfo.FileName = signtoolPath;
            process.StartInfo.Arguments = $"verify /pa \"{dllPath}\"";
            process.StartInfo.RedirectStandardOutput = true;
            process.StartInfo.RedirectStandardError = true;
            process.StartInfo.UseShellExecute = false;
            process.StartInfo.CreateNoWindow = true;

            process.Start();
            string output = process.StandardOutput.ReadToEnd();
            string error = process.StandardError.ReadToEnd();
            process.WaitForExit();

            if (!string.IsNullOrEmpty(error))
            {
                Debug.LogError("signtool error: " + error);
            }

            if (output.Contains("Successfully verified")){
                Debug.Log($"signtool.exe output: {output}");
                return true;
            }
            
            return false;
        }
        catch (System.Exception e)
        {
            Debug.LogError($"Exception while verifying DLL signature: {e}");
            return false;
        }
    }
}
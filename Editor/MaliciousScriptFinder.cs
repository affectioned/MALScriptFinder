using UnityEditor;
using UnityEngine;
using System.Text.RegularExpressions;
using System.Collections.Generic;
using System.IO;
using System.Linq;

public class MaliciousScriptFinder : EditorWindow
{
    private bool includeSubfolders = true;
    private string folderToCheck = "Assets";

    private const int MaxSeverity = 3;

    private readonly Dictionary<string, int> keywordSeverity = new Dictionary<string, int>
    {
            // Max Severity (3)
            {"password", 3},
            {"pass", 3},
            {"pwd", 3},
            {"secret", 3},
            {"credentials", 3},
            {"auth", 3},
            {"token", 3},
            {"apikey", 3},
            {"api_key", 3},
            {"access_token", 3},
            {"client_id", 3},
            {"secret_key", 3},
            {"authorization", 3},
            {"oauth_token", 3},
            {"refresh_token", 3},
            {"id_token", 3},
            {"authorization_code", 3},
            {"private_key", 3},
            {"rsa_key", 3},
            {"pem", 3},
            {"pkcs8", 3},
            {"secp256k1", 3},
            {"cookie", 3},
            {"discord_token", 3},
            {"WebClient", 3},
            {"HttpClient", 3},
            {"WebRequest", 3},
            {"WebResponse", 3},
            {"UnityWebRequest", 3},

            // Medium Severity (2)
            {"File.ReadAllText", 2},
            {"File.WriteAllText", 2},
            {"File.Copy", 2},
            {"File.Delete", 2},
            {"IO.File", 2},
            {"Serialization", 2},
            {"Json", 2},
            {"Xml", 2},
            {"NUnit.Framework.Serialization", 2},
            {"Newtonsoft.Json", 2},

            // Low Severity (1)
            {"Process.Start", 1},
            {"Process.Run", 1},
            {"System.Diagnostics.Process", 1},
            {"Registry.GetValue", 1},
            {"Registry.SetValue", 1},
            {"RegistryEditor", 1},
            {"RegistryKey", 1},
            {"Type", 1},
            {"MemberInfo", 1},
            {"MethodInfo", 1},
            {"FieldInfo", 1},
            {"Assembly", 1},
            {"Deserialize", 1},
            {"Deserialization", 1},
            {"Query", 1},
            {"ExecuteQuery", 1},
            {"SqlCommand", 1},
            {"SqlConnection", 1},
            {"Inject", 1},
            {"Script", 1},
            {"eval", 1},
            {"setTimeout", 1},
            {"setInterval", 1},
    };

    private bool runScanOnImport = true;

    private const string MenuItemPath = "Tools/Find Malicious Scripts";

    private static HashGenerator hashGenerator;

    [MenuItem(MenuItemPath)]
    public static void ShowWindow()
    {
        hashGenerator = new("Assets");
        GetWindow<MaliciousScriptFinder>();
    }

    public void OnGUI()
    {
        DrawMaliciousScriptFinderUI();
        DrawAutoScanToggle();
        hashGenerator.DrawFileHashGeneratorUI();
    }

    private void DrawMaliciousScriptFinderUI()
    {
        GUILayout.Label("Malicious Script Finder", EditorStyles.boldLabel);

        EditorGUILayout.LabelField(
            "This tool scans your Unity project for potential security vulnerabilities and malicious scripts. " +
            "It checks for keywords related to sensitive data exposure, file operations, network operations, " +
            "system interactions, and common vulnerabilities. You can specify the folder to check and choose " +
            "whether to include subfolders in the scan.",
            EditorStyles.wordWrappedLabel);

        includeSubfolders = EditorGUILayout.Toggle("Include Subfolders", includeSubfolders);
        folderToCheck = EditorGUILayout.TextField("Folder to Check", folderToCheck);

        if (GUILayout.Button("Scan Project"))
        {
            ScanProject();
        }
    }

    private void DrawAutoScanToggle()
    {
        GUILayout.Label("Auto Scan On Import", EditorStyles.boldLabel);
        runScanOnImport = EditorGUILayout.Toggle("Run Scan On Asset Import", runScanOnImport);
    }

    private void ScanProject()
    {
        if (!Directory.Exists(folderToCheck))
        {
            Debug.LogError($"Error: The specified folder '{folderToCheck}' does not exist.");
            return;
        }

        IEnumerable<string> filesToCheck = GetFilesToCheck(folderToCheck);

        Dictionary<string, int> folderSeverityCounts = new Dictionary<string, int>();

        foreach (string file in filesToCheck)
        {
            if (IsExcludedFile(file))
                continue;

            string content = "";

            // Read text content if the file is a .cs file
            if (file.EndsWith(".cs"))
            {
                content = File.ReadAllText(file);
            }
            // Log an error if the file is a .dll file
            else if (file.EndsWith(".dll"))
            {
                Debug.LogError($"Error: Binary file detected and skipped during analysis: {file}");
                continue;
            }

            int severity3Count = 0;

            foreach (KeyValuePair<string, int> entry in keywordSeverity)
            {
                string keyword = entry.Key;
                int severity = entry.Value;

                string pattern = $@"\b{keyword}\b";

                if (Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase))
                {
                    if (severity == MaxSeverity)
                    {
                        severity3Count++;
                        LogIssue(file, keyword, severity);
                    }
                    else
                    {
                        LogIssue(file, keyword, severity);
                    }
                }
            }

            if (severity3Count > 0)
            {
                folderSeverityCounts[file] = severity3Count;
            }
        }

        if (folderSeverityCounts.Count > 0)
        {
            LogMaxSeverityOccurrences(folderSeverityCounts);
        }
        else
        {
            Debug.Log("No severity 3 issues found in the specified folders.");
        }

        Debug.Log("Security check complete.");
    }

    private IEnumerable<string> GetFilesToCheck(string folder)
    {
        SearchOption searchOption = includeSubfolders ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;

        return Directory.GetFiles(folder, "*.*", searchOption)
                        .Where(file => !IsExcludedFile(file) && (file.EndsWith(".cs") || file.EndsWith(".dll")));
    }

    private bool IsExcludedFile(string file)
    {
        return file.EndsWith("MaliciousScriptFinder.cs");
    }

    private void LogIssue(string file, string keyword, int severity)
    {
        string logMessage = (severity == MaxSeverity)
            ? $"Maximum severity issue found in: {file}. Keyword: {keyword}"
            : $"Severity {severity} issue found in: {file}. Keyword: {keyword}";

        if (severity == MaxSeverity)
        {
            Debug.LogError(logMessage);
        }
        else
        {
            Debug.LogWarning(logMessage);
        }
    }

    private void LogMaxSeverityOccurrences(Dictionary<string, int> folderSeverityCounts)
    {
        var folderWithMaxSeverity3 = folderSeverityCounts.OrderByDescending(pair => pair.Value).First();
        Debug.LogError($"File '{folderWithMaxSeverity3.Key}' has the highest number of severity 3 occurrences: {folderWithMaxSeverity3.Value}");
    }
}

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using UnityEditor;
using UnityEngine;

public class HashGenerator
{
    private string folderToHash;
    public HashGenerator(string folderToHash)
    {
        this.folderToHash = folderToHash;
    }

    public void DrawFileHashGeneratorUI()
    {
        GUILayout.Label("File Hash Generator", EditorStyles.boldLabel);

        folderToHash = EditorGUILayout.TextField("Folder to Hash", folderToHash);

        if (GUILayout.Button("Generate Hash"))
        {
            GenerateHashForFolder(folderToHash);
        }
    }

    private void GenerateHashForFolder(string folderPath)
    {
        if (!Directory.Exists(folderPath))
        {
            Debug.LogError($"Error: The specified folder '{folderPath}' does not exist.");
            return;
        }

        StringBuilder hashStringBuilder = new StringBuilder();

        foreach (string filePath in Directory.GetFiles(folderPath, "*", SearchOption.AllDirectories))
        {
            using (FileStream stream = new FileStream(filePath, FileMode.Open, FileAccess.Read))
            {
                using (MD5 md5 = MD5.Create())
                {
                    byte[] hashBytes = md5.ComputeHash(stream);
                    string hashString = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                    hashStringBuilder.AppendLine($"{filePath}: {hashString}");
                }
            }
        }

        string result = hashStringBuilder.ToString();
        Debug.Log("Folder Hash (MD5):\n" + result);
    }
}

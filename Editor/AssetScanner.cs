using UnityEditor;
using UnityEngine;

public class AssetScanner : AssetPostprocessor
{
    void OnPreprocessAsset()
    {
        if (assetImporter == null)
        {
            Debug.LogError("AssetScanner: assetImporter is NULL!");
            return;
        }

        string assetPath = assetImporter.assetPath;

        Debug.Log($"AssetScanner: Preprocessing asset: {assetPath}");

        if (AssetValidator.IsAssetMalicious(assetPath))
        {
            Debug.LogError($"AssetScanner: Malicious content detected. Preventing import of: {assetPath}");
            AssetDatabase.DeleteAsset(assetPath); // Deletes the asset to prevent import
            AssetDatabase.Refresh();
        }
    }
}

public class AssetScanWindow : EditorWindow
{
    [MenuItem("Tools/Asset Scanner")]
    public static void ShowWindow()
    {
        GetWindow<AssetScanWindow>("Asset Scanner");
    }

    private void OnGUI()
    {
        GUILayout.Label("Asset Scanner", EditorStyles.boldLabel);
        if (GUILayout.Button("Scan Project for Malicious Assets"))
        {
            ScanAllAssets();
        }
    }

    private void ScanAllAssets()
    {
        string[] allAssets = AssetDatabase.GetAllAssetPaths();
        bool foundIssues = false;

        foreach (string assetPath in allAssets)
        {
            if (AssetValidator.IsAssetMalicious(assetPath))
            {
                Debug.LogWarning($"Malicious content detected: {assetPath}");
                foundIssues = true;
            }
        }

        if (!foundIssues)
        {
            Debug.Log("No malicious content found in assets.");
        }
    }
}
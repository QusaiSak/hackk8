# Windows PE File Analyzer with Malware Detection for Kaggle
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import joblib
import os
import hashlib
import time
from datetime import datetime
import seaborn as sns
from pathlib import Path
from IPython.display import display, HTML
import ipywidgets as widgets
from IPython.display import clear_output
import lief
from feature import PEFeatureExtractor

# Create necessary directories
os.makedirs("/kaggle/working/uploads", exist_ok=True)
os.makedirs("/kaggle/working/reports", exist_ok=True)

# Initialize PE Feature Extractor
pe_extractor = PEFeatureExtractor()

# Load the stacked malware detection model
print("Loading stacked malware detection model...")
try:
    stacked_model = joblib.load(
        "/kaggle/input/malware-detection-model/stacked_model.pkl"
    )
    print("Model loaded successfully!")
except Exception as e:
    print(f"Error loading model: {e}")
    print("Using heuristic-based detection only")
    stacked_model = None


# Function to extract features from a file
def extract_file_features(file_path):
    """Extract features from a file for malware prediction using EMBER + additional features"""
    features = {}
    try:
        # Basic file info
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)

        # Read file bytes
        with open(file_path, "rb") as f:
            data = f.read()

        # Calculate basic hashes
        md5_hash = hashlib.md5(data).hexdigest()
        sha256_hash = hashlib.sha256(data).hexdigest()

        # Extract EMBER features
        ember_features = pe_extractor.raw_features(data)
        processed_features = pe_extractor.process_raw_features(ember_features)

        # Basic features
        features = {
            "file_name": file_name,
            "file_size": file_size,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "timestamp": datetime.fromtimestamp(
                os.path.getctime(file_path)
            ).isoformat(),
        }

        # For simple PE detection
        is_pe = data[:2] == b"MZ"
        features["is_pe"] = is_pe

        # Extract ML features from EMBER + additional analysis
        ml_features = {}

        if "general" in ember_features:
            general_info = ember_features["general"]
            ml_features.update(
                {
                    "file_size": file_size,
                    "is_packed": int(general_info.get("entropy", 0) > 7.0),
                    "has_debug": general_info.get("has_debug", 0),
                    "has_relocations": general_info.get("has_relocations", 0),
                    "has_resources": general_info.get("has_resources", 0),
                    "has_signature": general_info.get("has_signature", 0),
                    "has_tls": general_info.get("has_tls", 0),
                    "num_imports": general_info.get("imports", 0),
                    "num_exports": general_info.get("exports", 0),
                }
            )

        # Add string features
        if "strings" in ember_features:
            strings_info = ember_features["strings"]
            ml_features.update(
                {
                    "num_strings": strings_info.get("numstrings", 0),
                    "avg_string_length": strings_info.get("avlength", 0),
                    "num_paths": strings_info.get("paths", 0),
                    "num_urls": strings_info.get("urls", 0),
                    "num_registry": strings_info.get("registry", 0),
                    "has_pdb": int(b".pdb" in data),
                    "string_entropy": strings_info.get("entropy", 0),
                }
            )

        # Add section features
        if "section" in ember_features:
            section_info = ember_features["section"]
            if isinstance(section_info, dict) and "sections" in section_info:
                sections = section_info["sections"]
                num_sections = len(sections)
                suspicious_sections = sum(
                    1 for s in sections if s.get("entropy", 0) > 7.0
                )
                executable_sections = sum(
                    1 for s in sections if "MEM_EXECUTE" in s.get("props", [])
                )

                ml_features.update(
                    {
                        "num_sections": num_sections,
                        "num_suspicious_sections": suspicious_sections,
                        "num_executable_sections": executable_sections,
                    }
                )

        # Calculate advanced threat score
        threat_score = 0
        if file_size < 30000 or file_size > 5000000:  # Suspicious size
            threat_score += 1
        if ml_features.get("is_packed", 0):  # Packed
            threat_score += 3
        if ml_features.get("num_suspicious_sections", 0) > 0:  # Suspicious sections
            threat_score += 2
        if ml_features.get("num_urls", 0) > 0:  # Network indicators
            threat_score += 1
        if ml_features.get("num_registry", 0) > 0:  # Registry operations
            threat_score += 1
        if not ml_features.get("has_signature", 0):  # Unsigned
            threat_score += 1
        if ml_features.get("has_debug", 0):  # Debug info present
            threat_score -= 1  # Legitimate software often has debug info

        ml_features["threat_score"] = threat_score
        features["ml_features"] = ml_features

        # Store raw EMBER features for advanced analysis
        features["ember_features"] = ember_features
        features["ember_vector"] = processed_features.tolist()

    except Exception as e:
        print(f"Error extracting features: {e}")
        features = {
            "file_name": os.path.basename(file_path),
            "error": str(e),
            "file_size": os.path.getsize(file_path) if os.path.exists(file_path) else 0,
        }

    return features


def analyze_file(file_path, model):
    """Analyze a file and predict if it's malware"""
    # Extract features
    features = extract_file_features(file_path)

    # Prepare features for prediction
    if "ml_features" in features:
        ml_features = features["ml_features"]
        feature_df = pd.DataFrame([ml_features])

        # Make prediction if model is available
        if model is not None:
            try:
                proba = model.predict_proba(feature_df)[0][1]
                is_malware = proba >= 0.65  # Using 0.65 threshold

                # Add prediction to features
                features["malware_probability"] = float(proba)
                features["is_malware"] = bool(is_malware)
            except Exception as e:
                print(f"Prediction error: {e}")
                # Fall back to heuristic
                proba = min(0.95, max(0.05, ml_features.get("threat_score", 0) / 15.0))
                is_malware = proba >= 0.65
                features["malware_probability"] = proba
                features["is_malware"] = is_malware
        else:
            # No model available, use heuristic
            threat_score = ml_features.get("threat_score", 0)
            features["malware_probability"] = min(0.95, max(0.05, threat_score / 15.0))
            features["is_malware"] = features["malware_probability"] >= 0.65

        # Determine risk level
        proba = features.get("malware_probability", 0)
        if proba >= 0.9:
            risk_level = "Critical"
        elif proba >= 0.7:
            risk_level = "High"
        elif proba >= 0.4:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        features["risk_level"] = risk_level

    else:
        # Couldn't extract ML features
        features["malware_probability"] = None
        features["is_malware"] = None
        features["risk_level"] = "Unknown"

    return features


def generate_report(analysis):
    """Generate a detailed report from the analysis"""
    ml_features = analysis.get("ml_features", {})
    ember_features = analysis.get("ember_features", {})

    report = f"""
==========================================
  WINDOWS PE MALWARE ANALYSIS REPORT
==========================================

FILE INFORMATION:
  Filename: {analysis.get('file_name', 'Unknown')}
  Size: {analysis.get('file_size', 0):,} bytes
  Created: {analysis.get('timestamp', 'Unknown')}

HASHES:
  MD5: {analysis.get('md5', 'Unknown')}
  SHA256: {analysis.get('sha256', 'Unknown')}

MALWARE DETECTION:
  Risk Level: {analysis.get('risk_level', 'Unknown')}
  Malware Probability: {analysis.get('malware_probability', 0):.2%}
  Verdict: {'MALICIOUS' if analysis.get('is_malware', False) else 'BENIGN'}

PE FILE ANALYSIS:
  Valid PE: {'Yes' if analysis.get('is_pe', False) else 'No'}
  Number of Sections: {ml_features.get('num_sections', 'Unknown')}
  Executable Sections: {ml_features.get('num_executable_sections', 'Unknown')}
  Suspicious Sections: {ml_features.get('num_suspicious_sections', 'Unknown')}
  Has Debug Info: {'Yes' if ml_features.get('has_debug', 0) == 1 else 'No'}
  Has Resources: {'Yes' if ml_features.get('has_resources', 0) == 1 else 'No'}
  Has Digital Signature: {'Yes' if ml_features.get('has_signature', 0) == 1 else 'No'}
  Has TLS: {'Yes' if ml_features.get('has_tls', 0) == 1 else 'No'}

IMPORTS AND EXPORTS:
  Number of Imports: {ml_features.get('num_imports', 'Unknown')}
  Number of Exports: {ml_features.get('num_exports', 'Unknown')}
  Has Relocations: {'Yes' if ml_features.get('has_relocations', 0) == 1 else 'No'}

STRING ANALYSIS:
  Number of Strings: {ml_features.get('num_strings', 'Unknown')}
  Average String Length: {ml_features.get('avg_string_length', 0):.1f}
  Has PDB Path: {'Yes' if ml_features.get('has_pdb', 0) == 1 else 'No'}
  Number of URLs: {ml_features.get('num_urls', 'Unknown')}
  Number of Registry Keys: {ml_features.get('num_registry', 'Unknown')}
  Number of File Paths: {ml_features.get('num_paths', 'Unknown')}
  String Entropy: {ml_features.get('string_entropy', 0):.2f}

SUSPICIOUS INDICATORS:
  Packed/Encrypted: {'Yes' if ml_features.get('is_packed', 0) == 1 else 'No'}
  Anti-Debug Features: {'Yes' if analysis.get('ml_features', {}).get('has_anti_debug', 0) == 1 else 'No'}
  Anti-VM Features: {'Yes' if analysis.get('ml_features', {}).get('has_anti_vm', 0) == 1 else 'No'}
  Network Capabilities: {'Yes' if analysis.get('ml_features', {}).get('has_network', 0) == 1 else 'No'}
  Accesses Registry: {'Yes' if ml_features.get('num_registry', 0) > 0 else 'No'}
  Contains URLs: {'Yes' if ml_features.get('num_urls', 0) > 0 else 'No'}

ASSESSMENT:
  Threat Score: {ml_features.get('threat_score', 0)} / 15
  """
    return report


def visualize_analysis(analysis):
    """Create visualizations for the analysis"""
    plt.figure(figsize=(15, 12))

    # Threat assessment chart
    plt.subplot(2, 3, 1)
    malware_probability = analysis.get("malware_probability", 0)
    if malware_probability is not None:
        plt.pie(
            [malware_probability, 1 - malware_probability],
            labels=["Malicious", "Benign"],
            colors=["red", "green"],
            autopct="%1.1f%%",
            startangle=90,
        )
        plt.title("Malware Probability")

    # Threat score bar chart
    plt.subplot(2, 3, 2)
    if "ml_features" in analysis:
        threat_score = analysis["ml_features"].get("threat_score", 0)
        plt.bar(["Threat Score"], [threat_score], color="orange")
        plt.ylim(0, 15)
        plt.title("Threat Score (out of 15)")

    # Section analysis
    plt.subplot(2, 3, 3)
    if "ml_features" in analysis:
        features = analysis["ml_features"]
        section_data = [
            features.get("num_sections", 0),
            features.get("num_executable_sections", 0),
            features.get("num_suspicious_sections", 0),
        ]
        plt.bar(["Total", "Executable", "Suspicious"], section_data)
        plt.title("Section Analysis")

    # Suspicious indicators
    plt.subplot(2, 3, 4)
    if "ml_features" in analysis:
        features = analysis["ml_features"]
        indicators = [
            "is_packed",
            "has_debug",
            "has_tls",
            "has_signature",
            "has_resources",
        ]
        names = ["Packed", "Debug", "TLS", "Signed", "Resources"]
        values = [features.get(ind, 0) for ind in indicators]
        plt.bar(names, values)
        plt.title("PE File Characteristics")
        plt.xticks(rotation=45)

    # String analysis
    plt.subplot(2, 3, 5)
    if "ml_features" in analysis:
        features = analysis["ml_features"]
        string_data = [
            features.get("num_urls", 0),
            features.get("num_registry", 0),
            features.get("num_paths", 0),
        ]
        plt.bar(["URLs", "Registry", "Paths"], string_data)
        plt.title("String Indicators")

    # Import/Export analysis
    plt.subplot(2, 3, 6)
    if "ml_features" in analysis:
        features = analysis["ml_features"]
        import_export = [features.get("num_imports", 0), features.get("num_exports", 0)]
        plt.bar(["Imports", "Exports"], import_export)
        plt.title("Imports & Exports")

    plt.tight_layout()
    return plt


def process_file(file_path):
    """Process a file through the malware detection system"""
    print(f"Analyzing file: {os.path.basename(file_path)}")

    # Perform analysis
    analysis = analyze_file(file_path, stacked_model)

    # Generate report
    report = generate_report(analysis)

    # Visualize analysis
    plot = visualize_analysis(analysis)

    # Save outputs
    report_path = os.path.join(
        "/kaggle/working/reports", f"{os.path.basename(file_path)}_report.txt"
    )
    with open(report_path, "w") as f:
        f.write(report)

    plot_path = os.path.join(
        "/kaggle/working/reports", f"{os.path.basename(file_path)}_analysis.png"
    )
    plot.savefig(plot_path)
    plt.close()

    print(f"Analysis complete. Report saved to {report_path}")
    print(f"Visualization saved to {plot_path}")

    return analysis, report_path, plot_path


def analyze_uploaded_files():
    """Analyze files uploaded to Kaggle"""
    input_dir = "/kaggle/input"

    # Find all files in the input directory
    all_files = []
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            # Skip files in model directory
            if "malware-detection-model" in root:
                continue
            all_files.append(os.path.join(root, file))

    if not all_files:
        print("No files found in /kaggle/input directory.")
        print("Please upload files using Kaggle's 'Add Data' button.")
        return

    print(f"Found {len(all_files)} files to analyze:")
    for i, file_path in enumerate(all_files, 1):
        print(f"{i}. {file_path}")

    results = []
    for file_path in all_files:
        try:
            analysis, report_path, plot_path = process_file(file_path)
            results.append(
                {
                    "file": os.path.basename(file_path),
                    "analysis": analysis,
                    "report_path": report_path,
                    "plot_path": plot_path,
                }
            )

            # Display the report and plot
            print("\n" + "=" * 80)
            print(f"Analysis results for {os.path.basename(file_path)}:")
            with open(report_path, "r") as f:
                print(f.read())

            plt.figure(figsize=(12, 10))
            img = plt.imread(plot_path)
            plt.imshow(img)
            plt.axis("off")
            plt.show()

        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            results.append({"file": os.path.basename(file_path), "error": str(e)})

    return results


# Create a simple UI for Kaggle
def create_ui():
    """Create a simple UI for file analysis"""
    clear_output()

    print(
        """
    ==========================================
      WINDOWS PE FILE MALWARE ANALYZER
    ==========================================
    """
    )

    # Instructions
    display(
        HTML(
            """
    <h3>How to use:</h3>
    <ol>
        <li>Click the "Add Data" button in the right sidebar</li>
        <li>Upload your files (EXE, DLL, etc.)</li>
        <li>Click the "Analyze Files" button below</li>
        <li>View the analysis results</li>
    </ol>
    """
        )
    )

    # Create analyze button
    analyze_btn = widgets.Button(
        description="Analyze Files",
        button_style="success",
        tooltip="Click to analyze uploaded files",
    )

    output = widgets.Output()

    def on_analyze_click(b):
        with output:
            clear_output()
            print("Starting analysis...")
            results = analyze_uploaded_files()
            if results:
                print("\nAnalysis complete!")
            else:
                print("\nNo files were analyzed.")

    analyze_btn.on_click(on_analyze_click)

    display(analyze_btn)
    display(output)


# Main execution
if __name__ == "__main__":
    create_ui()

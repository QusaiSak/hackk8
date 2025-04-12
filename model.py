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

# Create necessary directories
os.makedirs('/kaggle/working/uploads', exist_ok=True)
os.makedirs('/kaggle/working/reports', exist_ok=True)

# Load the stacked malware detection model
print("Loading stacked malware detection model...")
try:
    stacked_model = joblib.load('/kaggle/input/malware-detection-model/stacked_model.pkl')
    print("Model loaded successfully!")
except Exception as e:
    print(f"Error loading model: {e}")
    print("Using heuristic-based detection only")
    stacked_model = None

# Function to extract features from a file
def extract_file_features(file_path):
    """Extract basic features from a file for malware prediction"""
    features = {}
    try:
        # Basic file info
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        
        # Calculate hashes
        with open(file_path, 'rb') as f:
            data = f.read()
            md5_hash = hashlib.md5(data).hexdigest()
            sha256_hash = hashlib.sha256(data).hexdigest()
        
        # Entropy calculation
        byte_counts = {}
        for byte in data:
            byte_counts[byte] = byte_counts.get(byte, 0) + 1
        
        entropy = 0
        for count in byte_counts.values():
            probability = count / len(data)
            entropy -= probability * np.log2(probability)
        
        # Extract basic features
        features = {
            'file_name': file_name,
            'file_size': file_size,
            'md5': md5_hash,
            'sha256': sha256_hash,
            'entropy': entropy,
            'timestamp': datetime.fromtimestamp(os.path.getctime(file_path)).isoformat()
        }
        
        # For simple PE detection
        is_pe = data[:2] == b'MZ'
        features['is_pe'] = is_pe
        
        # Generate features for ML model
        ml_features = {
            'file_size': file_size,
            'is_packed': int(entropy > 7.0),
            'has_network': int(b'ws2_32' in data or b'wininet' in data),
            'has_anti_debug': int(b'IsDebuggerPresent' in data),
            'has_anti_vm': int(b'vmware' in data.lower() or b'virtualbox' in data.lower()),
            'num_sections': 5,  # Default/estimated value
            'num_imports': 50,  # Default/estimated value
            'num_exports': 5,   # Default/estimated value
            'num_resources': 10, # Default/estimated value
            'num_suspicious_sections': int(entropy > 7.0),
            'num_executable_sections': 2, # Default/estimated value
            'average_entropy': entropy,
            'risky_import_count': int(sum(x in data.lower() for x in [b'createprocess', b'virtualallocex', b'writeprocessmemory'])),
            'high_severity_indicators': int(entropy > 7.0 or b'IsDebuggerPresent' in data)
        }
        
        # Calculate threat score
        threat_score = 0
        if file_size < 30000 or file_size > 5000000:  # Suspicious size
            threat_score += 1
        if entropy > 7.0:  # High entropy (possible packing)
            threat_score += 3
        if b'IsDebuggerPresent' in data:  # Anti-debugging
            threat_score += 2
        if b'ws2_32' in data or b'wininet' in data:  # Network capabilities
            threat_score += 1
        if b'CreateProcess' in data or b'VirtualAllocEx' in data:  # Suspicious API
            threat_score += 2
            
        ml_features['threat_score'] = threat_score
        features['ml_features'] = ml_features
        
    except Exception as e:
        print(f"Error extracting features: {e}")
        features = {
            'file_name': os.path.basename(file_path),
            'error': str(e),
            'file_size': os.path.getsize(file_path) if os.path.exists(file_path) else 0
        }
    
    return features

def analyze_file(file_path, model):
    """Analyze a file and predict if it's malware"""
    # Extract features
    features = extract_file_features(file_path)
    
    # Prepare features for prediction
    if 'ml_features' in features:
        ml_features = features['ml_features']
        feature_df = pd.DataFrame([ml_features])
        
        # Make prediction if model is available
        if model is not None:
            try:
                proba = model.predict_proba(feature_df)[0][1]
                is_malware = proba >= 0.65  # Using 0.65 threshold
                
                # Add prediction to features
                features['malware_probability'] = float(proba)
                features['is_malware'] = bool(is_malware)
            except Exception as e:
                print(f"Prediction error: {e}")
                # Fall back to heuristic
                proba = min(0.95, max(0.05, ml_features.get('threat_score', 0) / 15.0))
                is_malware = proba >= 0.65
                features['malware_probability'] = proba
                features['is_malware'] = is_malware
        else:
            # No model available, use heuristic
            threat_score = ml_features.get('threat_score', 0)
            features['malware_probability'] = min(0.95, max(0.05, threat_score / 15.0))
            features['is_malware'] = features['malware_probability'] >= 0.65
        
        # Determine risk level
        proba = features.get('malware_probability', 0)
        if proba >= 0.9:
            risk_level = "Critical"
        elif proba >= 0.7:
            risk_level = "High"
        elif proba >= 0.4:
            risk_level = "Medium"
        else:
            risk_level = "Low"
            
        features['risk_level'] = risk_level
        
    else:
        # Couldn't extract ML features
        features['malware_probability'] = None
        features['is_malware'] = None
        features['risk_level'] = "Unknown"
    
    return features

def generate_report(analysis):
    """Generate a detailed report from the analysis"""
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

FILE PROPERTIES:
  Entropy: {analysis.get('entropy', 0):.2f}
  PE File: {'Yes' if analysis.get('is_pe', False) else 'No'}

INDICATORS:
  High Entropy (Possible Packing): {'Yes' if analysis.get('entropy', 0) > 7.0 else 'No'}
  Network Capabilities: {'Yes' if analysis.get('ml_features', {}).get('has_network', 0) == 1 else 'No'}
  Anti-Debugging: {'Yes' if analysis.get('ml_features', {}).get('has_anti_debug', 0) == 1 else 'No'}
  Anti-VM: {'Yes' if analysis.get('ml_features', {}).get('has_anti_vm', 0) == 1 else 'No'}
  Suspicious APIs: {'Yes' if analysis.get('ml_features', {}).get('risky_import_count', 0) > 0 else 'No'}

ASSESSMENT:
  Threat Score: {analysis.get('ml_features', {}).get('threat_score', 0)} / 15
  """
    
    return report

def visualize_analysis(analysis):
    """Create visualizations for the analysis"""
    plt.figure(figsize=(12, 10))
    
    # Threat assessment chart
    plt.subplot(2, 2, 1)
    malware_probability = analysis.get('malware_probability', 0)
    if malware_probability is not None:
        plt.pie([malware_probability, 1-malware_probability], 
                labels=['Malicious', 'Benign'],
                colors=['red', 'green'],
                autopct='%1.1f%%',
                startangle=90)
        plt.title('Malware Probability')
    else:
        plt.text(0.5, 0.5, 'Prediction not available', 
                 horizontalalignment='center', verticalalignment='center')
        plt.axis('off')
    
    # Threat score bar chart
    plt.subplot(2, 2, 2)
    if 'ml_features' in analysis:
        threat_score = analysis['ml_features'].get('threat_score', 0)
        plt.bar(['Threat Score'], [threat_score], color='orange')
        plt.ylim(0, 15)
        plt.title('Threat Score (out of 15)')
    else:
        plt.text(0.5, 0.5, 'Threat score not available', 
                 horizontalalignment='center', verticalalignment='center')
        plt.axis('off')
    
    # Indicator bar chart
    plt.subplot(2, 1, 2)
    if 'ml_features' in analysis:
        features = analysis['ml_features']
        indicators = ['is_packed', 'has_network', 'has_anti_debug', 'has_anti_vm', 'high_severity_indicators']
        names = ['Packed', 'Network', 'Anti-Debug', 'Anti-VM', 'High Severity']
        values = [features.get(ind, 0) for ind in indicators]
        
        plt.bar(names, values)
        plt.title('Security Indicators')
        plt.ylim(0, 1.1)
    else:
        plt.text(0.5, 0.5, 'Indicators not available', 
                 horizontalalignment='center', verticalalignment='center')
        plt.axis('off')
    
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
    report_path = os.path.join('/kaggle/working/reports', f"{os.path.basename(file_path)}_report.txt")
    with open(report_path, 'w') as f:
        f.write(report)
    
    plot_path = os.path.join('/kaggle/working/reports', f"{os.path.basename(file_path)}_analysis.png")
    plot.savefig(plot_path)
    plt.close()
    
    print(f"Analysis complete. Report saved to {report_path}")
    print(f"Visualization saved to {plot_path}")
    
    return analysis, report_path, plot_path

def analyze_uploaded_files():
    """Analyze files uploaded to Kaggle"""
    input_dir = '/kaggle/input'
    
    # Find all files in the input directory
    all_files = []
    for root, dirs, files in os.walk(input_dir):
        for file in files:
            # Skip files in model directory
            if 'malware-detection-model' in root:
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
            results.append({
                'file': os.path.basename(file_path),
                'analysis': analysis,
                'report_path': report_path,
                'plot_path': plot_path
            })
            
            # Display the report and plot
            print("\n" + "="*80)
            print(f"Analysis results for {os.path.basename(file_path)}:")
            with open(report_path, 'r') as f:
                print(f.read())
            
            plt.figure(figsize=(12, 10))
            img = plt.imread(plot_path)
            plt.imshow(img)
            plt.axis('off')
            plt.show()
            
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            results.append({
                'file': os.path.basename(file_path),
                'error': str(e)
            })
    
    return results

# Create a simple UI for Kaggle
def create_ui():
    """Create a simple UI for file analysis"""
    clear_output()
    
    print("""
    ==========================================
      WINDOWS PE FILE MALWARE ANALYZER
    ==========================================
    """)
    
    # Instructions
    display(HTML("""
    <h3>How to use:</h3>
    <ol>
        <li>Click the "Add Data" button in the right sidebar</li>
        <li>Upload your files (EXE, DLL, etc.)</li>
        <li>Click the "Analyze Files" button below</li>
        <li>View the analysis results</li>
    </ol>
    """))
    
    # Create analyze button
    analyze_btn = widgets.Button(
        description="Analyze Files",
        button_style='success',
        tooltip='Click to analyze uploaded files'
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

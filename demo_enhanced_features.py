#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Framework Demo
Demonstrates the new enhanced database, filtering, and reporting capabilities
"""

import subprocess
import sys
from pathlib import Path
import json
import time

def print_header(title):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(f"🎯 {title}")
    print("=" * 60)

def print_section(title):
    """Print formatted section"""
    print(f"\n📋 {title}")
    print("-" * 40)

def demonstrate_cli_options():
    """Demonstrate new CLI options"""
    print_header("Enhanced CLI Options Demo")
    
    print("🔧 New filtering options added to both frameworks:")
    print("   --min-confidence: Set confidence threshold (0.0-1.0)")
    print("   --exclude-severities: Exclude specific severity levels")
    print("   --exclude-fps: Automatically exclude false positives")
    print("   --no-filtering: Disable all filtering")
    print("   --export-formats: Choose export formats (html, json, csv, xml)")
    
    print("\n💡 Example commands:")
    print("   # High confidence only, exclude info findings")
    print("   python3 z3muth.py --target example.com --quick-scan \\")
    print("     --min-confidence 0.7 --exclude-severities info")
    
    print("\n   # Export only JSON and CSV, no filtering")
    print("   python3 azaz_el_ultimate.py --target example.com --quick-scan \\")
    print("     --no-filtering --export-formats json csv")

def demonstrate_file_exports():
    """Demonstrate file export capabilities"""
    print_header("Automated File Export Demo")
    
    # Check if test results exist
    results_dir = Path("results")
    if results_dir.exists():
        scan_dirs = [d for d in results_dir.iterdir() if d.is_dir()]
        
        if scan_dirs:
            latest_scan = max(scan_dirs, key=lambda d: d.stat().st_mtime)
            print(f"📁 Latest scan results: {latest_scan.name}")
            
            # List generated files
            files = list(latest_scan.glob("*"))
            if files:
                print(f"📄 Generated files ({len(files)} total):")
                for file_path in files:
                    size = file_path.stat().st_size
                    print(f"   • {file_path.name:<20} ({size:,} bytes)")
                    
                    # Show sample content for small files
                    if file_path.suffix == '.json' and size < 10000:
                        try:
                            with open(file_path) as f:
                                data = json.load(f)
                            findings_count = len(data.get('findings', []))
                            risk_score = data.get('scan_metadata', {}).get('risk_score', 0)
                            print(f"     └─ {findings_count} findings, risk score: {risk_score:.2f}")
                        except:
                            pass
                
                # Show HTML report sample
                html_file = latest_scan / "scan_results.html"
                if html_file.exists():
                    print(f"\n🌐 HTML Report Features:")
                    content = html_file.read_text()
                    if 'severity-card' in content or 'summary-card' in content:
                        print("   ✅ Interactive severity cards")
                    if 'expandable' in content or 'onclick' in content:
                        print("   ✅ Expandable finding details")
                    if 'Security Scan Report' in content:
                        print("   ✅ Professional report layout")
                    print(f"   📊 Report size: {len(content):,} characters")
            else:
                print("❌ No files found in scan directory")
        else:
            print("❌ No scan results found")
    else:
        print("❌ Results directory not found")

def demonstrate_database_features():
    """Demonstrate database capabilities"""
    print_header("Enhanced Database Features Demo")
    
    # Check if databases exist
    db_files = [
        ("z3muth_data.db", "Z3MUTH Database"),
        ("azaz_el_data.db", "Azaz-El Ultimate Database"),
    ]
    
    for db_file, db_name in db_files:
        db_path = Path(db_file)
        if db_path.exists():
            size = db_path.stat().st_size
            print(f"💾 {db_name}: {size:,} bytes")
            
            # Try to show table info using sqlite3
            try:
                result = subprocess.run([
                    'sqlite3', str(db_path), 
                    '.tables'
                ], capture_output=True, text=True, timeout=5)
                
                if result.returncode == 0:
                    tables = result.stdout.strip().split()
                    print(f"   📊 Tables: {', '.join(tables)}")
                    
                    # Count records in key tables
                    for table in ['scans', 'findings']:
                        if table in tables:
                            count_result = subprocess.run([
                                'sqlite3', str(db_path),
                                f'SELECT COUNT(*) FROM {table};'
                            ], capture_output=True, text=True, timeout=5)
                            
                            if count_result.returncode == 0:
                                count = count_result.stdout.strip()
                                print(f"   📈 {table}: {count} records")
                
            except Exception as e:
                print(f"   ⚠️  Could not read database structure: {e}")
        else:
            print(f"❌ {db_name}: Not found")

def demonstrate_filtering_features():
    """Demonstrate filtering capabilities"""
    print_header("Intelligent Filtering Features Demo")
    
    print("🧠 Enhanced filtering capabilities:")
    print("   ✅ Automated false positive detection")
    print("   ✅ Pattern-based filtering rules")
    print("   ✅ Confidence-based filtering") 
    print("   ✅ Duplicate removal")
    print("   ✅ High-value finding enhancement")
    print("   ✅ Context-aware filtering")
    
    # Show filter rules
    filter_rules_file = Path("config/filter_rules.json")
    if filter_rules_file.exists():
        try:
            with open(filter_rules_file) as f:
                rules = json.load(f)
            
            print(f"\n📋 Loaded {len(rules)} filter rules:")
            for rule in rules[:5]:  # Show first 5 rules
                name = rule.get('name', 'Unknown')
                action = rule.get('action', 'unknown')
                enabled = rule.get('enabled', False)
                status = "✅" if enabled else "❌"
                print(f"   {status} {name} ({action})")
                
            if len(rules) > 5:
                print(f"   ... and {len(rules) - 5} more rules")
                
        except Exception as e:
            print(f"   ⚠️  Could not read filter rules: {e}")
    else:
        print("❌ Filter rules file not found")

def show_usage_examples():
    """Show practical usage examples"""
    print_header("Practical Usage Examples")
    
    examples = [
        {
            "title": "Basic Scan with Enhanced Features",
            "command": "python3 z3muth.py --target example.com --quick-scan",
            "description": "Performs scan with automatic filtering and exports to all formats"
        },
        {
            "title": "High Confidence Findings Only",
            "command": "python3 z3muth.py --target example.com --ultimate-scan --min-confidence 0.8",
            "description": "Only includes findings with 80%+ confidence"
        },
        {
            "title": "Exclude Low Severity Issues",
            "command": "python3 azaz_el_ultimate.py --target example.com --ultimate-scan --exclude-severities low info",
            "description": "Focuses on medium, high, and critical findings only"
        },
        {
            "title": "JSON and CSV Export Only",
            "command": "python3 z3muth.py --target example.com --quick-scan --export-formats json csv",
            "description": "Exports results in machine-readable formats only"
        },
        {
            "title": "No Filtering (Raw Results)",
            "command": "python3 azaz_el_ultimate.py --target example.com --quick-scan --no-filtering",
            "description": "Disables all filtering for raw, unprocessed results"
        }
    ]
    
    for i, example in enumerate(examples, 1):
        print(f"\n{i}. {example['title']}")
        print(f"   Command: {example['command']}")
        print(f"   Description: {example['description']}")

def main():
    """Main demo function"""
    print("🚀 Enhanced Azaz-El Framework Demonstration")
    print("🔧 Version: 7.0.0-ULTIMATE with Enhanced Features")
    print(f"📅 Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Run demonstrations
    demonstrate_cli_options()
    demonstrate_file_exports()
    demonstrate_database_features()
    demonstrate_filtering_features()
    show_usage_examples()
    
    print_header("Summary")
    print("✅ Enhanced database with comprehensive schema")
    print("✅ Automated export to JSON, CSV, XML, and HTML")
    print("✅ Intelligent filtering with false positive detection")
    print("✅ High-value finding enhancement and prioritization")
    print("✅ Command-line options for filtering configuration")
    print("✅ Backward compatibility with existing features")
    
    print("\n🎯 Next Steps:")
    print("1. Run test_enhanced_framework.py to verify all features")
    print("2. Try the new CLI options with your targets")
    print("3. Review generated reports in the results/ directory")
    print("4. Customize filter rules in config/filter_rules.json")
    
    print("\n📖 For detailed documentation, see README.md")

if __name__ == "__main__":
    main()
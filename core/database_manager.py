#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Database Manager for Azaz-El Framework
Comprehensive database management with automated results file generation
"""

import json
import sqlite3
import csv
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional, Union
import logging
from dataclasses import asdict

class EnhancedDatabaseManager:
    """Enhanced database manager with comprehensive storage and export capabilities"""
    
    def __init__(self, db_path: str, logger: Optional[logging.Logger] = None):
        self.db_path = Path(db_path)
        self.logger = logger or logging.getLogger(__name__)
        self.db_connection = None
        self._initialize_database()
    
    def _initialize_database(self):
        """Initialize comprehensive database schema"""
        try:
            self.db_connection = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self.db_connection.row_factory = sqlite3.Row  # Enable dict-like access
            
            # Enhanced scans table
            self.db_connection.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    target_type TEXT DEFAULT 'unknown',
                    scan_type TEXT DEFAULT 'general',
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT DEFAULT 'pending',
                    phase TEXT DEFAULT 'initialization',
                    findings_count INTEGER DEFAULT 0,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    info_count INTEGER DEFAULT 0,
                    errors_count INTEGER DEFAULT 0,
                    warnings_count INTEGER DEFAULT 0,
                    duration_seconds INTEGER DEFAULT 0,
                    scan_config TEXT,
                    metadata TEXT,
                    risk_score REAL DEFAULT 0.0,
                    compliance_status TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Enhanced findings table
            self.db_connection.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    finding_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    severity TEXT DEFAULT 'info',
                    category TEXT DEFAULT 'general',
                    cvss_score REAL DEFAULT 0.0,
                    cvss_vector TEXT,
                    cwe TEXT,
                    owasp_category TEXT,
                    affected_url TEXT,
                    affected_parameter TEXT,
                    confidence REAL DEFAULT 1.0,
                    exploitability REAL DEFAULT 0.0,
                    impact REAL DEFAULT 0.0,
                    risk_score REAL DEFAULT 0.0,
                    evidence TEXT,
                    proof_of_concept TEXT,
                    remediation TEXT,
                    refs TEXT,
                    false_positive BOOLEAN DEFAULT 0,
                    verified BOOLEAN DEFAULT 0,
                    exploited BOOLEAN DEFAULT 0,
                    compliance_mapping TEXT,
                    business_impact TEXT,
                    technical_impact TEXT,
                    metadata TEXT,
                    raw_output TEXT,
                    tool_name TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Tools usage tracking
            self.db_connection.execute("""
                CREATE TABLE IF NOT EXISTS tools_usage (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    tool_name TEXT NOT NULL,
                    scan_id TEXT,
                    target TEXT,
                    command_line TEXT,
                    start_time TEXT,
                    end_time TEXT,
                    duration_seconds INTEGER,
                    status TEXT,
                    exit_code INTEGER,
                    output_size INTEGER,
                    findings_generated INTEGER DEFAULT 0,
                    error_message TEXT,
                    performance_metrics TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Scan reports tracking
            self.db_connection.execute("""
                CREATE TABLE IF NOT EXISTS reports (
                    report_id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    format TEXT NOT NULL,
                    file_path TEXT,
                    file_size INTEGER,
                    generation_time TEXT,
                    status TEXT DEFAULT 'generated',
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Filter rules and patterns
            self.db_connection.execute("""
                CREATE TABLE IF NOT EXISTS filter_rules (
                    rule_id TEXT PRIMARY KEY,
                    rule_name TEXT NOT NULL,
                    rule_type TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    action TEXT DEFAULT 'mark_fp',
                    confidence_adjustment REAL DEFAULT 0.0,
                    enabled BOOLEAN DEFAULT 1,
                    description TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Performance metrics
            self.db_connection.execute("""
                CREATE TABLE IF NOT EXISTS performance_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    metric_name TEXT NOT NULL,
                    metric_value REAL NOT NULL,
                    metric_unit TEXT,
                    timestamp TEXT,
                    metadata TEXT
                )
            """)
            
            # Create comprehensive indices
            indices = [
                "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)",
                "CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)",
                "CREATE INDEX IF NOT EXISTS idx_scans_start_time ON scans(start_time)",
                "CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)",
                "CREATE INDEX IF NOT EXISTS idx_findings_scan_id ON findings(scan_id)",
                "CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)",
                "CREATE INDEX IF NOT EXISTS idx_findings_cvss_score ON findings(cvss_score)",
                "CREATE INDEX IF NOT EXISTS idx_findings_false_positive ON findings(false_positive)",
                "CREATE INDEX IF NOT EXISTS idx_tools_tool_name ON tools_usage(tool_name)",
                "CREATE INDEX IF NOT EXISTS idx_tools_scan_id ON tools_usage(scan_id)",
                "CREATE INDEX IF NOT EXISTS idx_reports_scan_id ON reports(scan_id)",
                "CREATE INDEX IF NOT EXISTS idx_reports_format ON reports(format)",
                "CREATE INDEX IF NOT EXISTS idx_filter_rules_type ON filter_rules(rule_type)",
                "CREATE INDEX IF NOT EXISTS idx_performance_scan_id ON performance_metrics(scan_id)"
            ]
            
            for index_sql in indices:
                self.db_connection.execute(index_sql)
            
            self.db_connection.commit()
            self.logger.info("✅ Enhanced database schema initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Database initialization failed: {e}")
            raise
    
    def save_scan_result(self, scan_result: Any, export_formats: List[str] = None) -> bool:
        """Save scan result to database and export to multiple formats"""
        try:
            if export_formats is None:
                export_formats = ["json", "csv", "xml", "html"]
            
            # Save to database
            self._save_scan_to_db(scan_result)
            
            # Export to files
            export_success = self._export_scan_results(scan_result, export_formats)
            
            self.logger.info(f"✅ Scan {scan_result.scan_id} saved to database and exported")
            return export_success
            
        except Exception as e:
            self.logger.error(f"Failed to save scan result: {e}")
            return False
    
    def _save_scan_to_db(self, scan_result: Any):
        """Save scan data to database tables"""
        try:
            # Calculate severity counts
            severity_counts = self._calculate_severity_counts(scan_result.findings)
            
            # Calculate duration
            duration = 0
            if scan_result.end_time and scan_result.start_time:
                duration = int((scan_result.end_time - scan_result.start_time).total_seconds())
            
            # Save scan record
            self.db_connection.execute("""
                INSERT OR REPLACE INTO scans 
                (scan_id, target, target_type, scan_type, start_time, end_time, status, phase, 
                 findings_count, critical_count, high_count, medium_count, low_count, info_count,
                 errors_count, warnings_count, duration_seconds, scan_config, metadata, risk_score,
                 updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan_result.scan_id,
                getattr(scan_result.target, 'target', str(scan_result.target)) if scan_result.target else '',
                getattr(scan_result.target, 'target_type', 'unknown') if scan_result.target else 'unknown',
                getattr(scan_result, 'scan_type', 'general'),
                scan_result.start_time.isoformat() if scan_result.start_time else '',
                scan_result.end_time.isoformat() if scan_result.end_time else None,
                scan_result.status,
                getattr(scan_result, 'phase', 'completed'),
                len(scan_result.findings),
                severity_counts.get('critical', 0),
                severity_counts.get('high', 0),
                severity_counts.get('medium', 0),
                severity_counts.get('low', 0),
                severity_counts.get('info', 0),
                len(getattr(scan_result, 'errors', [])),
                len(getattr(scan_result, 'warnings', [])),
                duration,
                json.dumps(getattr(scan_result, 'scan_config', {})),
                json.dumps(getattr(scan_result, 'metadata', {})),
                self._calculate_overall_risk_score(scan_result.findings),
                datetime.now().isoformat()
            ))
            
            # Save findings
            for finding in scan_result.findings:
                self._save_finding_to_db(finding, scan_result.scan_id)
            
            self.db_connection.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to save scan to database: {e}")
            raise
    
    def _save_finding_to_db(self, finding: Any, scan_id: str):
        """Save individual finding to database"""
        try:
            self.db_connection.execute("""
                INSERT OR REPLACE INTO findings
                (finding_id, scan_id, title, description, severity, category, cvss_score, cvss_vector,
                 cwe, owasp_category, affected_url, affected_parameter, confidence, exploitability,
                 impact, risk_score, evidence, proof_of_concept, remediation, refs,
                 false_positive, verified, exploited, compliance_mapping, business_impact,
                 technical_impact, metadata, raw_output, tool_name, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                getattr(finding, 'id', f"{scan_id}_{finding.title[:50]}"),
                scan_id,
                finding.title,
                getattr(finding, 'description', ''),
                finding.severity,
                getattr(finding, 'category', 'general'),
                getattr(finding, 'cvss_score', 0.0),
                getattr(finding, 'cvss_vector', ''),
                getattr(finding, 'cwe', ''),
                getattr(finding, 'owasp_category', ''),
                getattr(finding, 'url', ''),
                getattr(finding, 'parameter', ''),
                getattr(finding, 'confidence', 1.0),
                getattr(finding, 'exploitability', 0.0),
                getattr(finding, 'impact', 0.0),
                getattr(finding, 'calculate_risk_score', lambda: 0.0)(),
                getattr(finding, 'evidence', ''),
                getattr(finding, 'proof_of_concept', ''),
                getattr(finding, 'remediation', ''),
                json.dumps(getattr(finding, 'refs', [])),
                getattr(finding, 'false_positive', False),
                getattr(finding, 'verified', False),
                getattr(finding, 'exploited', False),
                json.dumps(getattr(finding, 'compliance_mapping', {})),
                getattr(finding, 'business_impact', ''),
                getattr(finding, 'technical_impact', ''),
                json.dumps(getattr(finding, 'metadata', {})),
                getattr(finding, 'raw_output', ''),
                getattr(finding, 'tool', 'unknown'),
                datetime.now().isoformat()
            ))
            
        except Exception as e:
            self.logger.error(f"Failed to save finding to database: {e}")
            raise
    
    def _export_scan_results(self, scan_result: Any, formats: List[str]) -> bool:
        """Export scan results to multiple file formats"""
        try:
            output_dir = Path(f"results/{scan_result.scan_id}")
            output_dir.mkdir(parents=True, exist_ok=True)
            
            export_success = True
            
            # JSON export
            if "json" in formats:
                json_success = self._export_to_json(scan_result, output_dir)
                export_success = export_success and json_success
            
            # CSV export
            if "csv" in formats:
                csv_success = self._export_to_csv(scan_result, output_dir)
                export_success = export_success and csv_success
            
            # XML export
            if "xml" in formats:
                xml_success = self._export_to_xml(scan_result, output_dir)
                export_success = export_success and xml_success
            
            # HTML export
            if "html" in formats:
                html_success = self._export_to_html(scan_result, output_dir)
                export_success = export_success and html_success
            
            return export_success
            
        except Exception as e:
            self.logger.error(f"Failed to export scan results: {e}")
            return False
    
    def _export_to_json(self, scan_result: Any, output_dir: Path) -> bool:
        """Export scan results to JSON format"""
        try:
            json_file = output_dir / "scan_results.json"
            
            # Prepare data for JSON export
            export_data = {
                "scan_metadata": {
                    "scan_id": scan_result.scan_id,
                    "target": getattr(scan_result.target, 'target', str(scan_result.target)) if scan_result.target else '',
                    "start_time": scan_result.start_time.isoformat() if scan_result.start_time else '',
                    "end_time": scan_result.end_time.isoformat() if scan_result.end_time else '',
                    "status": scan_result.status,
                    "total_findings": len(scan_result.findings),
                    "risk_score": self._calculate_overall_risk_score(scan_result.findings)
                },
                "findings": [self._serialize_finding_for_export(finding) for finding in scan_result.findings],
                "summary": self._generate_summary(scan_result.findings),
                "export_timestamp": datetime.now().isoformat()
            }
            
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            # Record export in database
            self._record_export(scan_result.scan_id, "json", str(json_file), json_file.stat().st_size)
            
            self.logger.info(f"✅ JSON export completed: {json_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"JSON export failed: {e}")
            return False
    
    def _export_to_csv(self, scan_result: Any, output_dir: Path) -> bool:
        """Export scan results to CSV format"""
        try:
            csv_file = output_dir / "scan_results.csv"
            
            fieldnames = [
                'finding_id', 'title', 'severity', 'cvss_score', 'confidence',
                'category', 'affected_url', 'description', 'evidence',
                'remediation', 'false_positive', 'verified'
            ]
            
            with open(csv_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                
                for finding in scan_result.findings:
                    row = {
                        'finding_id': getattr(finding, 'id', ''),
                        'title': finding.title,
                        'severity': finding.severity,
                        'cvss_score': getattr(finding, 'cvss_score', 0.0),
                        'confidence': getattr(finding, 'confidence', 1.0),
                        'category': getattr(finding, 'category', 'general'),
                        'affected_url': getattr(finding, 'url', ''),
                        'description': getattr(finding, 'description', ''),
                        'evidence': getattr(finding, 'evidence', ''),
                        'remediation': getattr(finding, 'remediation', ''),
                        'false_positive': getattr(finding, 'false_positive', False),
                        'verified': getattr(finding, 'verified', False)
                    }
                    writer.writerow(row)
            
            # Record export in database
            self._record_export(scan_result.scan_id, "csv", str(csv_file), csv_file.stat().st_size)
            
            self.logger.info(f"✅ CSV export completed: {csv_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"CSV export failed: {e}")
            return False
    
    def _export_to_xml(self, scan_result: Any, output_dir: Path) -> bool:
        """Export scan results to XML format"""
        try:
            xml_file = output_dir / "scan_results.xml"
            
            root = ET.Element("ScanResults")
            
            # Metadata
            metadata = ET.SubElement(root, "Metadata")
            ET.SubElement(metadata, "ScanId").text = scan_result.scan_id
            ET.SubElement(metadata, "Target").text = getattr(scan_result.target, 'target', str(scan_result.target)) if scan_result.target else ''
            ET.SubElement(metadata, "StartTime").text = scan_result.start_time.isoformat() if scan_result.start_time else ''
            ET.SubElement(metadata, "Status").text = scan_result.status
            ET.SubElement(metadata, "TotalFindings").text = str(len(scan_result.findings))
            
            # Findings
            findings_elem = ET.SubElement(root, "Findings")
            for finding in scan_result.findings:
                finding_elem = ET.SubElement(findings_elem, "Finding")
                ET.SubElement(finding_elem, "Title").text = finding.title
                ET.SubElement(finding_elem, "Severity").text = finding.severity
                ET.SubElement(finding_elem, "Description").text = getattr(finding, 'description', '')
                ET.SubElement(finding_elem, "CVSS").text = str(getattr(finding, 'cvss_score', 0.0))
                ET.SubElement(finding_elem, "Confidence").text = str(getattr(finding, 'confidence', 1.0))
            
            tree = ET.ElementTree(root)
            tree.write(xml_file, encoding='utf-8', xml_declaration=True)
            
            # Record export in database
            self._record_export(scan_result.scan_id, "xml", str(xml_file), xml_file.stat().st_size)
            
            self.logger.info(f"✅ XML export completed: {xml_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"XML export failed: {e}")
            return False
    
    def _export_to_html(self, scan_result: Any, output_dir: Path) -> bool:
        """Export scan results to HTML format"""
        try:
            html_file = output_dir / "scan_results.html"
            
            # Generate HTML content
            html_content = self._generate_html_report(scan_result)
            
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            # Record export in database
            self._record_export(scan_result.scan_id, "html", str(html_file), html_file.stat().st_size)
            
            self.logger.info(f"✅ HTML export completed: {html_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"HTML export failed: {e}")
            return False
    
    def _generate_html_report(self, scan_result: Any) -> str:
        """Generate HTML report content"""
        severity_counts = self._calculate_severity_counts(scan_result.findings)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report - {scan_result.scan_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        .header {{ text-align: center; border-bottom: 2px solid #333; padding-bottom: 20px; margin-bottom: 30px; }}
        .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }}
        .summary-card {{ background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }}
        .critical {{ background-color: #dc3545; color: white; }}
        .high {{ background-color: #fd7e14; color: white; }}
        .medium {{ background-color: #ffc107; color: black; }}
        .low {{ background-color: #28a745; color: white; }}
        .info {{ background-color: #17a2b8; color: white; }}
        .findings {{ margin-top: 30px; }}
        .finding {{ border: 1px solid #ddd; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }}
        .finding-header {{ padding: 15px; background-color: #f8f9fa; font-weight: bold; cursor: pointer; }}
        .finding-content {{ padding: 15px; display: none; }}
        .finding.expanded .finding-content {{ display: block; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 10px; border: 1px solid #ddd; text-align: left; }}
        th {{ background-color: #f8f9fa; }}
    </style>
    <script>
        function toggleFinding(element) {{
            element.parentElement.classList.toggle('expanded');
        }}
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Security Scan Report</h1>
            <p><strong>Scan ID:</strong> {scan_result.scan_id}</p>
            <p><strong>Target:</strong> {getattr(scan_result.target, 'target', str(scan_result.target)) if scan_result.target else 'Unknown'}</p>
            <p><strong>Scan Time:</strong> {scan_result.start_time.strftime('%Y-%m-%d %H:%M:%S') if scan_result.start_time else 'Unknown'}</p>
            <p><strong>Status:</strong> {scan_result.status}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card critical">
                <h3>Critical</h3>
                <p>{severity_counts.get('critical', 0)}</p>
            </div>
            <div class="summary-card high">
                <h3>High</h3>
                <p>{severity_counts.get('high', 0)}</p>
            </div>
            <div class="summary-card medium">
                <h3>Medium</h3>
                <p>{severity_counts.get('medium', 0)}</p>
            </div>
            <div class="summary-card low">
                <h3>Low</h3>
                <p>{severity_counts.get('low', 0)}</p>
            </div>
            <div class="summary-card info">
                <h3>Info</h3>
                <p>{severity_counts.get('info', 0)}</p>
            </div>
        </div>
        
        <div class="findings">
            <h2>Detailed Findings</h2>
        """
        
        for i, finding in enumerate(scan_result.findings):
            severity_class = finding.severity.lower()
            html += f"""
            <div class="finding">
                <div class="finding-header {severity_class}" onclick="toggleFinding(this)">
                    [{finding.severity}] {finding.title}
                </div>
                <div class="finding-content">
                    <p><strong>Description:</strong> {getattr(finding, 'description', 'N/A')}</p>
                    <p><strong>CVSS Score:</strong> {getattr(finding, 'cvss_score', 0.0)}</p>
                    <p><strong>Confidence:</strong> {getattr(finding, 'confidence', 1.0)}</p>
                    <p><strong>Evidence:</strong> {getattr(finding, 'evidence', 'N/A')}</p>
                    <p><strong>Remediation:</strong> {getattr(finding, 'remediation', 'N/A')}</p>
                </div>
            </div>
            """
        
        html += """
        </div>
        
        <div style="margin-top: 30px; text-align: center; color: #666;">
            <p>Report generated by Azaz-El Ultimate Framework</p>
            <p>Generated on: """ + datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
    
    def _calculate_severity_counts(self, findings: List[Any]) -> Dict[str, int]:
        """Calculate counts by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for finding in findings:
            severity = finding.severity.lower()
            if severity in counts:
                counts[severity] += 1
        return counts
    
    def _calculate_overall_risk_score(self, findings: List[Any]) -> float:
        """Calculate overall risk score"""
        if not findings:
            return 0.0
        
        severity_weights = {'critical': 10.0, 'high': 7.5, 'medium': 5.0, 'low': 2.5, 'info': 1.0}
        total_score = 0.0
        
        for finding in findings:
            severity = finding.severity.lower()
            weight = severity_weights.get(severity, 1.0)
            confidence = getattr(finding, 'confidence', 1.0)
            total_score += weight * confidence
        
        return min(10.0, total_score / len(findings))
    
    def _generate_summary(self, findings: List[Any]) -> Dict[str, Any]:
        """Generate summary statistics"""
        severity_counts = self._calculate_severity_counts(findings)
        
        return {
            "total_findings": len(findings),
            "severity_distribution": severity_counts,
            "risk_score": self._calculate_overall_risk_score(findings),
            "top_categories": self._get_top_categories(findings),
            "false_positive_rate": self._calculate_false_positive_rate(findings)
        }
    
    def _get_top_categories(self, findings: List[Any]) -> List[Dict[str, Any]]:
        """Get top finding categories"""
        categories = {}
        for finding in findings:
            category = getattr(finding, 'category', 'general')
            categories[category] = categories.get(category, 0) + 1
        
        return [{"category": k, "count": v} for k, v in sorted(categories.items(), key=lambda x: x[1], reverse=True)[:5]]
    
    def _calculate_false_positive_rate(self, findings: List[Any]) -> float:
        """Calculate false positive rate"""
        if not findings:
            return 0.0
        
        fp_count = sum(1 for finding in findings if getattr(finding, 'false_positive', False))
        return fp_count / len(findings)
    
    def _serialize_finding_for_export(self, finding: Any) -> Dict[str, Any]:
        """Serialize finding for export"""
        return {
            "id": getattr(finding, 'id', ''),
            "title": finding.title,
            "description": getattr(finding, 'description', ''),
            "severity": finding.severity,
            "cvss_score": getattr(finding, 'cvss_score', 0.0),
            "confidence": getattr(finding, 'confidence', 1.0),
            "category": getattr(finding, 'category', 'general'),
            "affected_url": getattr(finding, 'url', ''),
            "evidence": getattr(finding, 'evidence', ''),
            "remediation": getattr(finding, 'remediation', ''),
            "false_positive": getattr(finding, 'false_positive', False),
            "verified": getattr(finding, 'verified', False),
            "metadata": getattr(finding, 'metadata', {})
        }
    
    def _record_export(self, scan_id: str, format_type: str, file_path: str, file_size: int):
        """Record export information in database"""
        try:
            report_id = f"{scan_id}_{format_type}_{int(datetime.now().timestamp())}"
            
            self.db_connection.execute("""
                INSERT INTO reports
                (report_id, scan_id, report_type, format, file_path, file_size, generation_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                report_id,
                scan_id,
                "scan_results",
                format_type,
                file_path,
                file_size,
                datetime.now().isoformat()
            ))
            
            self.db_connection.commit()
            
        except Exception as e:
            self.logger.error(f"Failed to record export: {e}")
    
    def get_scan_results(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve scan results from database"""
        try:
            cursor = self.db_connection.execute("""
                SELECT * FROM scans WHERE scan_id = ?
            """, (scan_id,))
            
            scan_row = cursor.fetchone()
            if not scan_row:
                return None
            
            # Get findings
            cursor = self.db_connection.execute("""
                SELECT * FROM findings WHERE scan_id = ? ORDER BY risk_score DESC
            """, (scan_id,))
            
            findings = cursor.fetchall()
            
            return {
                "scan": dict(scan_row),
                "findings": [dict(finding) for finding in findings]
            }
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve scan results: {e}")
            return None
    
    def list_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """List recent scans"""
        try:
            cursor = self.db_connection.execute("""
                SELECT scan_id, target, start_time, status, findings_count, risk_score
                FROM scans 
                ORDER BY created_at DESC 
                LIMIT ?
            """, (limit,))
            
            return [dict(row) for row in cursor.fetchall()]
            
        except Exception as e:
            self.logger.error(f"Failed to list scans: {e}")
            return []
    
    def close(self):
        """Close database connection"""
        if self.db_connection:
            self.db_connection.close()
            self.logger.info("Database connection closed")
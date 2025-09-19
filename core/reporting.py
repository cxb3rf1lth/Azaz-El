"""
Advanced Reporting Engine
Comprehensive security assessment reporting with multiple formats and analytics
"""

import json
import jinja2
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional
import base64
import hashlib
import csv
import xml.etree.ElementTree as ET

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.logging import get_logger

class AdvancedReportGenerator:
    """Advanced security report generation with multiple formats"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = get_logger("report-generator")
        
        # Risk scoring matrix
        self.risk_matrix = {
            "Critical": {"score": 9.0, "color": "#dc3545", "priority": 1},
            "High": {"score": 7.5, "color": "#fd7e14", "priority": 2},
            "Medium": {"score": 5.0, "color": "#ffc107", "priority": 3},
            "Low": {"score": 2.5, "color": "#28a745", "priority": 4},
            "Info": {"score": 1.0, "color": "#17a2b8", "priority": 5}
        }
        
        # Compliance frameworks mapping
        self.compliance_frameworks = {
            "OWASP": {
                "name": "OWASP Top 10",
                "categories": ["A01", "A02", "A03", "A04", "A05", "A06", "A07", "A08", "A09", "A10"]
            },
            "NIST": {
                "name": "NIST Cybersecurity Framework",
                "categories": ["ID", "PR", "DE", "RS", "RC"]
            },
            "ISO27001": {
                "name": "ISO/IEC 27001",
                "categories": ["A.5", "A.6", "A.7", "A.8", "A.9", "A.10", "A.11", "A.12", "A.13", "A.14"]
            },
            "PCI-DSS": {
                "name": "Payment Card Industry Data Security Standard",
                "categories": ["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"]
            }
        }
    
    def generate_comprehensive_report(self, run_dir: Path, findings: Dict[str, Any], 
                                    scan_metadata: Dict[str, Any]) -> bool:
        """Generate comprehensive security assessment report with enhanced error handling"""
        start_time = datetime.now()
        report_context = {
            "run_dir": str(run_dir),
            "total_findings": sum(len(f) if isinstance(f, list) else 1 for f in findings.values()),
            "scanner_types": list(findings.keys())
        }
        
        try:
            self.logger.info("🚀 Starting comprehensive security report generation")
            
            # Validate inputs
            if not self._validate_inputs(findings, scan_metadata):
                self.logger.error("❌ Input validation failed")
                return False
            
            # Create output directory if it doesn't exist
            run_dir.mkdir(parents=True, exist_ok=True)
            
            # Process and analyze findings with progress tracking
            self.logger.info("📊 Processing findings data...")
            processed_findings = self._process_findings(findings)
            report_context["processed_findings_count"] = len(processed_findings)
            
            # Generate risk analysis
            self.logger.info("⚡ Generating risk analysis...")
            risk_analysis = self._generate_risk_analysis(processed_findings)
            
            # Generate compliance mapping
            self.logger.info("📋 Generating compliance mapping...")
            compliance_mapping = self._generate_compliance_mapping(processed_findings)
            
            # Generate executive summary
            self.logger.info("📈 Generating executive summary...")
            executive_summary = self._generate_executive_summary(processed_findings, risk_analysis)
            
            # Prepare report data with enhanced metadata
            report_data = {
                "metadata": {
                    **scan_metadata,
                    "report_generation_time": datetime.now().isoformat(),
                    "report_generation_duration": None,  # Will be set at the end
                    "report_version": "2.0",
                    "framework_version": "7.0.0-ULTIMATE"
                },
                "findings": processed_findings,
                "risk_analysis": risk_analysis,
                "compliance_mapping": compliance_mapping,
                "executive_summary": executive_summary,
                "statistics": {
                    "total_findings": len(processed_findings),
                    "scan_duration": scan_metadata.get("duration", 0),
                    "findings_by_scanner": {k: len(v) if isinstance(v, list) else 1 for k, v in findings.items()}
                }
            }
            
            # Generate multiple report formats with individual error handling
            results = {}
            self.logger.info("📄 Generating report files...")
            
            # HTML Report (Interactive Dashboard)
            results["html"] = self._generate_html_report_safe(run_dir, report_data)
            
            # JSON Report (Machine Readable)
            results["json"] = self._generate_json_report_safe(run_dir, report_data)
            
            # CSV Report (Data Analysis)
            results["csv"] = self._generate_csv_report_safe(run_dir, processed_findings)
            
            # XML Report (Integration)
            results["xml"] = self._generate_xml_report_safe(run_dir, report_data)
            
            # Calculate generation duration
            generation_duration = (datetime.now() - start_time).total_seconds()
            report_data["metadata"]["report_generation_duration"] = generation_duration
            
            # Log generation summary
            successful_formats = [fmt for fmt, success in results.items() if success]
            failed_formats = [fmt for fmt, success in results.items() if not success]
            
            self.logger.info(f"✅ Report generation completed in {generation_duration:.2f}s")
            
            if failed_formats:
                self.logger.warning(f"⚠️ Some formats failed: {failed_formats}")
            
            return len(successful_formats) > 0  # Success if at least one format was generated
            
        except Exception as e:
            generation_duration = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"❌ Report generation failed after {generation_duration:.2f}s: {e}")
            return False
    
    def _validate_inputs(self, findings: Dict[str, Any], scan_metadata: Dict[str, Any]) -> bool:
        """Validate inputs before report generation"""
        try:
            # Validate findings structure
            if not isinstance(findings, dict):
                self.logger.error("❌ Findings must be a dictionary")
                return False
            
            if not findings:
                self.logger.warning("⚠️ No findings provided, generating empty report")
                return True
            
            # Validate scan metadata
            if not isinstance(scan_metadata, dict):
                self.logger.error("❌ Scan metadata must be a dictionary")
                return False
            
            # Check for required metadata fields
            required_fields = ["scan_id", "start_time"]
            missing_fields = [field for field in required_fields if field not in scan_metadata]
            if missing_fields:
                self.logger.warning(f"⚠️ Missing metadata fields: {missing_fields}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"❌ Input validation error: {e}")
            return False
    
    def _generate_html_report_safe(self, run_dir: Path, report_data: Dict[str, Any]) -> bool:
        """Generate HTML report with enhanced error handling"""
        try:
            return self._generate_html_report(run_dir, report_data)
        except Exception as e:
            self.logger.error(f"❌ HTML report generation failed: {e}", exc_info=True)
            return False
    
    def _generate_json_report_safe(self, run_dir: Path, report_data: Dict[str, Any]) -> bool:
        """Generate JSON report with enhanced error handling"""
        try:
            return self._generate_json_report(run_dir, report_data)
        except Exception as e:
            self.logger.error(f"❌ JSON report generation failed: {e}", exc_info=True)
            return False
    
    def _generate_csv_report_safe(self, run_dir: Path, findings: List[Dict[str, Any]]) -> bool:
        """Generate CSV report with enhanced error handling"""
        try:
            return self._generate_csv_report(run_dir, findings)
        except Exception as e:
            self.logger.error(f"❌ CSV report generation failed: {e}", exc_info=True)
            return False
    
    def _generate_xml_report_safe(self, run_dir: Path, report_data: Dict[str, Any]) -> bool:
        """Generate XML report with enhanced error handling"""
        try:
            return self._generate_xml_report(run_dir, report_data)
        except Exception as e:
            self.logger.error(f"❌ XML report generation failed: {e}", exc_info=True)
            return False
    
    
    def _process_findings(self, findings: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process and standardize findings from all scanners"""
        processed = []
        
        for scanner_type, scanner_findings in findings.items():
            if isinstance(scanner_findings, list):
                for finding in scanner_findings:
                    processed_finding = self._standardize_finding(finding, scanner_type)
                    processed.append(processed_finding)
        
        # Sort by severity and confidence
        processed.sort(key=lambda x: (
            self.risk_matrix.get(x.get("severity", "Low"), {"priority": 5})["priority"],
            -self._calculate_confidence_score(x.get("confidence", "Low"))
        ))
        
        return processed
    
    def _standardize_finding(self, finding: Dict[str, Any], scanner_type: str) -> Dict[str, Any]:
        """Standardize finding format across different scanners"""
        
        # Handle different finding formats (dataclass instances, dicts, etc.)
        if hasattr(finding, '__dict__'):
            finding_dict = finding.__dict__
        else:
            finding_dict = finding
        
        standardized = {
            "id": self._generate_finding_id(finding_dict),
            "scanner": scanner_type,
            "title": finding_dict.get("vuln_type", "Unknown Vulnerability"),
            "severity": finding_dict.get("severity", "Low"),
            "confidence": finding_dict.get("confidence", "Low"),
            "description": finding_dict.get("description", ""),
            "remediation": finding_dict.get("remediation", ""),
            "target": finding_dict.get("target", finding_dict.get("url", finding_dict.get("endpoint", ""))),
            "evidence": finding_dict.get("evidence", finding_dict.get("payload", "")),
            "cwe_ids": finding_dict.get("cwe_ids", [finding_dict.get("cwe_id", "")]),
            "cve_ids": finding_dict.get("cve_ids", []),
            "risk_score": self._calculate_risk_score(finding_dict),
            "owasp_category": self._map_to_owasp(finding_dict),
            "compliance_impact": finding_dict.get("compliance_impact", []),
            "timestamp": finding_dict.get("timestamp", datetime.now().isoformat())
        }
        
        # Add scanner-specific fields
        if scanner_type == "api":
            standardized.update({
                "endpoint": finding_dict.get("endpoint", ""),
                "method": finding_dict.get("method", ""),
                "parameter": finding_dict.get("parameter", "")
            })
        elif scanner_type == "cloud":
            standardized.update({
                "cloud_provider": finding_dict.get("cloud_provider", ""),
                "service": finding_dict.get("service", ""),
                "region": finding_dict.get("region", "")
            })
        elif scanner_type == "infrastructure":
            standardized.update({
                "port": finding_dict.get("port", 0),
                "service": finding_dict.get("service", ""),
                "version": finding_dict.get("version", "")
            })
        
        return standardized
    
    def _generate_finding_id(self, finding: Dict[str, Any]) -> str:
        """Generate unique ID for finding"""
        content = f"{finding.get('vuln_type', '')}{finding.get('target', '')}{finding.get('evidence', '')}"
        return hashlib.md5(content.encode()).hexdigest()[:8]
    
    def _calculate_risk_score(self, finding: Dict[str, Any]) -> float:
        """Calculate numerical risk score for finding"""
        severity = finding.get("severity", "Low")
        confidence = finding.get("confidence", "Low")
        
        severity_score = self.risk_matrix.get(severity, {"score": 1.0})["score"]
        confidence_multiplier = self._calculate_confidence_score(confidence) / 100.0
        
        return round(severity_score * confidence_multiplier, 2)
    
    def _calculate_confidence_score(self, confidence: str) -> float:
        """Convert confidence level to numerical score"""
        confidence_scores = {
            "High": 95.0,
            "Medium": 75.0,
            "Low": 50.0
        }
        return confidence_scores.get(confidence, 50.0)
    
    def _map_to_owasp(self, finding: Dict[str, Any]) -> str:
        """Map finding to OWASP Top 10 category"""
        vuln_type = finding.get("vuln_type", "").lower()
        
        owasp_mapping = {
            "sql injection": "A03",
            "xss": "A03",
            "cross-site scripting": "A03",
            "authentication": "A07",
            "authorization": "A01",
            "session": "A07",
            "csrf": "A01",
            "file upload": "A04",
            "path traversal": "A01",
            "information disclosure": "A01",
            "security misconfiguration": "A05",
            "ssl": "A02",
            "tls": "A02",
            "encryption": "A02",
            "logging": "A09",
            "monitoring": "A09"
        }
        
        for keyword, category in owasp_mapping.items():
            if keyword in vuln_type:
                return category
        
        return "A06"  # Default to Vulnerable and Outdated Components
    
    def _generate_risk_analysis(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive risk analysis"""
        
        # Severity distribution
        severity_distribution = {}
        for severity in self.risk_matrix.keys():
            severity_distribution[severity] = len([f for f in findings if f["severity"] == severity])
        
        # Risk trends and patterns
        scanner_distribution = {}
        target_distribution = {}
        
        for finding in findings:
            scanner = finding["scanner"]
            target = finding["target"]
            
            scanner_distribution[scanner] = scanner_distribution.get(scanner, 0) + 1
            target_distribution[target] = target_distribution.get(target, 0) + 1
        
        # Calculate overall risk score
        total_risk_score = sum(finding["risk_score"] for finding in findings)
        avg_risk_score = total_risk_score / len(findings) if findings else 0
        
        # Risk categories
        critical_findings = [f for f in findings if f["severity"] == "Critical"]
        high_findings = [f for f in findings if f["severity"] == "High"]
        
        return {
            "overall_risk_level": self._determine_overall_risk_level(avg_risk_score, critical_findings, high_findings),
            "total_risk_score": round(total_risk_score, 2),
            "average_risk_score": round(avg_risk_score, 2),
            "severity_distribution": severity_distribution,
            "scanner_distribution": scanner_distribution,
            "target_distribution": dict(list(target_distribution.items())[:10]),  # Top 10 targets
            "critical_count": len(critical_findings),
            "high_count": len(high_findings),
            "recommendations": self._generate_risk_recommendations(findings)
        }
    
    def _determine_overall_risk_level(self, avg_score: float, critical: List, high: List) -> str:
        """Determine overall risk level for the assessment"""
        if len(critical) > 0:
            return "Critical"
        elif len(high) > 5:
            return "High"
        elif avg_score > 5.0:
            return "Medium"
        else:
            return "Low"
    
    def _generate_risk_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate prioritized remediation recommendations"""
        recommendations = []
        
        # Group findings by type
        vuln_types = {}
        for finding in findings:
            vuln_type = finding["title"]
            if vuln_type not in vuln_types:
                vuln_types[vuln_type] = []
            vuln_types[vuln_type].append(finding)
        
        # Generate recommendations based on most common/critical issues
        sorted_vulns = sorted(vuln_types.items(), 
                             key=lambda x: (len(x[1]), max(f["risk_score"] for f in x[1])), 
                             reverse=True)
        
        for vuln_type, vuln_findings in sorted_vulns[:5]:  # Top 5 recommendations
            count = len(vuln_findings)
            max_severity = max(f["severity"] for f in vuln_findings)
            
            if count > 1:
                recommendations.append(
                    f"Address {count} instances of {vuln_type} (Severity: {max_severity})"
                )
            else:
                recommendations.append(
                    f"Fix {vuln_type} vulnerability (Severity: {max_severity})"
                )
        
        return recommendations
    
    def _generate_compliance_mapping(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Map findings to compliance frameworks"""
        compliance_results = {}
        
        for framework_id, framework in self.compliance_frameworks.items():
            compliance_results[framework_id] = {
                "name": framework["name"],
                "total_findings": 0,
                "critical_findings": 0,
                "categories_affected": set(),
                "compliance_score": 0
            }
        
        # Map findings to frameworks
        for finding in findings:
            compliance_impact = finding.get("compliance_impact", [])
            owasp_category = finding.get("owasp_category", "")
            
            for framework_id in compliance_impact:
                if framework_id in compliance_results:
                    compliance_results[framework_id]["total_findings"] += 1
                    if finding["severity"] == "Critical":
                        compliance_results[framework_id]["critical_findings"] += 1
            
            # Map OWASP categories
            if owasp_category and "OWASP" in compliance_results:
                compliance_results["OWASP"]["total_findings"] += 1
                compliance_results["OWASP"]["categories_affected"].add(owasp_category)
                if finding["severity"] == "Critical":
                    compliance_results["OWASP"]["critical_findings"] += 1
        
        # Calculate compliance scores
        for framework_id, result in compliance_results.items():
            total_categories = len(self.compliance_frameworks[framework_id]["categories"])
            affected_categories = len(result["categories_affected"])
            
            if total_categories > 0:
                result["compliance_score"] = round(
                    ((total_categories - affected_categories) / total_categories) * 100, 1
                )
            else:
                result["compliance_score"] = 100.0
            
            # Convert set to list for JSON serialization
            result["categories_affected"] = list(result["categories_affected"])
        
        return compliance_results
    
    def _generate_executive_summary(self, findings: List[Dict[str, Any]], 
                                   risk_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary for leadership"""
        
        total_findings = len(findings)
        critical_count = risk_analysis["critical_count"]
        high_count = risk_analysis["high_count"]
        
        # Business impact assessment
        business_impact = self._assess_business_impact(findings)
        
        # Key metrics
        key_metrics = {
            "total_vulnerabilities": total_findings,
            "critical_vulnerabilities": critical_count,
            "high_risk_vulnerabilities": high_count,
            "overall_risk_level": risk_analysis["overall_risk_level"],
            "security_score": self._calculate_security_score(risk_analysis),
            "remediation_priority": "Critical" if critical_count > 0 else "High" if high_count > 3 else "Medium"
        }
        
        # Executive recommendations
        exec_recommendations = self._generate_executive_recommendations(findings, risk_analysis)
        
        return {
            "overview": self._generate_overview_text(key_metrics),
            "key_metrics": key_metrics,
            "business_impact": business_impact,
            "recommendations": exec_recommendations,
            "next_steps": self._generate_next_steps(risk_analysis)
        }
    
    def _assess_business_impact(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess potential business impact of vulnerabilities"""
        
        high_impact_vulns = [
            f for f in findings 
            if f["severity"] in ["Critical", "High"] and 
            any(keyword in f["title"].lower() for keyword in 
                ["sql injection", "authentication", "authorization", "data", "admin"])
        ]
        
        data_exposure_risk = len([
            f for f in findings 
            if any(keyword in f["title"].lower() for keyword in 
                   ["disclosure", "exposure", "leak", "dump"])
        ])
        
        availability_risk = len([
            f for f in findings
            if any(keyword in f["title"].lower() for keyword in
                   ["dos", "denial", "crash", "hang"])
        ])
        
        return {
            "data_breach_risk": "High" if data_exposure_risk > 2 else "Medium" if data_exposure_risk > 0 else "Low",
            "service_disruption_risk": "High" if availability_risk > 2 else "Medium" if availability_risk > 0 else "Low",
            "compliance_violations": len(set().union(*[f.get("compliance_impact", []) for f in findings])),
            "potential_financial_impact": self._estimate_financial_impact(high_impact_vulns),
            "reputation_risk": "High" if len(high_impact_vulns) > 5 else "Medium" if len(high_impact_vulns) > 0 else "Low"
        }
    
    def _estimate_financial_impact(self, high_impact_vulns: List[Dict[str, Any]]) -> str:
        """Estimate potential financial impact"""
        if len(high_impact_vulns) > 10:
            return "$500K - $5M+"
        elif len(high_impact_vulns) > 5:
            return "$100K - $500K"
        elif len(high_impact_vulns) > 0:
            return "$10K - $100K"
        else:
            return "< $10K"
    
    def _calculate_security_score(self, risk_analysis: Dict[str, Any]) -> int:
        """Calculate overall security score (0-100)"""
        base_score = 100
        
        # Deduct points based on findings
        critical_penalty = risk_analysis["critical_count"] * 20
        high_penalty = risk_analysis["high_count"] * 10
        
        # Cap penalties
        total_penalty = min(critical_penalty + high_penalty, 90)
        
        return max(base_score - total_penalty, 10)
    
    def _generate_executive_recommendations(self, findings: List[Dict[str, Any]], 
                                          risk_analysis: Dict[str, Any]) -> List[str]:
        """Generate executive-level recommendations"""
        recommendations = []
        
        if risk_analysis["critical_count"] > 0:
            recommendations.append("Immediate action required: Address critical vulnerabilities within 24-48 hours")
        
        if risk_analysis["high_count"] > 3:
            recommendations.append("Implement comprehensive security review and remediation program")
        
        # Add specific recommendations based on finding patterns
        scanner_dist = risk_analysis["scanner_distribution"]
        
        if scanner_dist.get("web", 0) > 5:
            recommendations.append("Enhance web application security testing and code review processes")
        
        if scanner_dist.get("infrastructure", 0) > 3:
            recommendations.append("Review network security architecture and server hardening procedures")
        
        if scanner_dist.get("api", 0) > 2:
            recommendations.append("Implement API security gateway and authentication mechanisms")
        
        if scanner_dist.get("cloud", 0) > 2:
            recommendations.append("Review cloud security configurations and access controls")
        
        return recommendations
    
    def _generate_next_steps(self, risk_analysis: Dict[str, Any]) -> List[str]:
        """Generate actionable next steps"""
        steps = []
        
        if risk_analysis["critical_count"] > 0:
            steps.append("1. Assemble incident response team for critical vulnerability remediation")
            steps.append("2. Implement temporary mitigations for critical findings")
        
        steps.extend([
            f"{len(steps)+1}. Prioritize remediation based on risk scores and business impact",
            f"{len(steps)+2}. Establish regular security scanning schedule",
            f"{len(steps)+3}. Implement security awareness training for development teams",
            f"{len(steps)+4}. Schedule follow-up assessment in 30-60 days"
        ])
        
        return steps
    
    def _generate_overview_text(self, metrics: Dict[str, Any]) -> str:
        """Generate executive overview text"""
        return (
            f"Security assessment completed identifying {metrics['total_vulnerabilities']} "
            f"total vulnerabilities with {metrics['critical_vulnerabilities']} critical and "
            f"{metrics['high_risk_vulnerabilities']} high-risk findings. "
            f"Overall security posture rated as {metrics['overall_risk_level']} risk with a "
            f"security score of {metrics['security_score']}/100."
        )
    
    def _generate_html_report(self, run_dir: Path, report_data: Dict[str, Any]) -> bool:
        """Generate interactive HTML dashboard report"""
        try:
            template_content = self._get_html_template()
            
            # Create Jinja2 template
            template = jinja2.Template(template_content)
            
            # Render report
            html_content = template.render(
                report=report_data,
                risk_matrix=self.risk_matrix,
                generation_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            )
            
            # Save HTML report
            report_file = run_dir / "security_assessment_report.html"
            with open(report_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"HTML report generated: {report_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"HTML report generation failed: {e}")
            return False
    
    def _generate_json_report(self, run_dir: Path, report_data: Dict[str, Any]) -> bool:
        """Generate machine-readable JSON report with validation"""
        try:
            report_file = run_dir / "security_assessment_report.json"
            
            # Validate JSON serialization before writing
            try:
                json_test = json.dumps(report_data, default=str, indent=2)
            except (TypeError, ValueError) as e:
                self.logger.error(f"❌ JSON serialization validation failed: {e}")
                return False
            
            # Write JSON file with proper encoding
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(report_data, f, indent=2, default=str, ensure_ascii=False)
            
            # Verify file was written and is valid JSON
            try:
                with open(report_file, 'r', encoding='utf-8') as f:
                    json.load(f)
                file_size = report_file.stat().st_size
                self.logger.info(f"✅ JSON report generated: {report_file} ({file_size} bytes)")
                return True
            except json.JSONDecodeError as e:
                self.logger.error(f"❌ Generated JSON file is invalid: {e}")
                return False
            
        except Exception as e:
            self.logger.error(f"❌ JSON report generation failed: {e}")
            return False
    
    def _generate_csv_report(self, run_dir: Path, findings: List[Dict[str, Any]]) -> bool:
        """Generate CSV report for data analysis with validation"""
        try:
            report_file = run_dir / "security_findings.csv"
            
            if not findings:
                self.logger.info("⚠️ No findings to export to CSV")
                # Create empty CSV with headers
                with open(report_file, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.writer(f)
                    writer.writerow(['message'])
                    writer.writerow(['No findings detected'])
                return True
            
            # Sanitize and validate findings data
            sanitized_findings = []
            for i, finding in enumerate(findings):
                try:
                    # Ensure all values are strings or can be converted to strings
                    sanitized_finding = {}
                    for key, value in finding.items():
                        if value is None:
                            sanitized_finding[key] = ""
                        elif isinstance(value, (list, dict)):
                            sanitized_finding[key] = json.dumps(value, default=str)
                        else:
                            sanitized_finding[key] = str(value)
                    sanitized_findings.append(sanitized_finding)
                except Exception as e:
                    self.logger.warning(f"⚠️ Skipping malformed finding {i}: {e}")
                    continue
            
            if not sanitized_findings:
                self.logger.error("❌ No valid findings after sanitization")
                return False
            
            # Get all unique field names
            fieldnames = set()
            for finding in sanitized_findings:
                fieldnames.update(finding.keys())
            
            # Sort fieldnames for consistent output
            fieldnames = sorted(list(fieldnames))
            
            # Write CSV file
            with open(report_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(sanitized_findings)
            
            # Verify file was written
            file_size = report_file.stat().st_size
            self.logger.info(f"✅ CSV report generated: {report_file} ({len(sanitized_findings)} records, {file_size} bytes)")
            return True
            
        except Exception as e:
            self.logger.error(f"❌ CSV report generation failed: {e}")
            return False
    
    def _generate_xml_report(self, run_dir: Path, report_data: Dict[str, Any]) -> bool:
        """Generate XML report for integration"""
        try:
            root = ET.Element("SecurityAssessmentReport")
            
            # Add metadata
            metadata = ET.SubElement(root, "Metadata")
            for key, value in report_data["metadata"].items():
                elem = ET.SubElement(metadata, key.replace(" ", "_"))
                elem.text = str(value)
            
            # Add findings
            findings_elem = ET.SubElement(root, "Findings")
            for finding in report_data["findings"]:
                finding_elem = ET.SubElement(findings_elem, "Finding")
                for key, value in finding.items():
                    elem = ET.SubElement(finding_elem, key)
                    if isinstance(value, list):
                        elem.text = ", ".join(str(v) for v in value)
                    else:
                        elem.text = str(value)
            
            # Save XML
            tree = ET.ElementTree(root)
            report_file = run_dir / "security_assessment_report.xml"
            tree.write(report_file, encoding='utf-8', xml_declaration=True)
            
            self.logger.info(f"XML report generated: {report_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"XML report generation failed: {e}")
            return False
    
    def _get_html_template(self) -> str:
        """Get HTML report template"""
        return '''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Azaz-El Security Assessment Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; text-align: center; margin-bottom: 30px; }
        .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .metric-card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .metric-value { font-size: 2em; font-weight: bold; margin-bottom: 5px; }
        .severity-critical { color: #dc3545; }
        .severity-high { color: #fd7e14; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #28a745; }
        .severity-info { color: #17a2b8; }
        .section { background: white; margin-bottom: 30px; padding: 25px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .section h2 { color: #2c3e50; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #ecf0f1; }
        .findings-table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        .findings-table th, .findings-table td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        .findings-table th { background-color: #f8f9fa; font-weight: 600; }
        .badge { padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: 600; text-transform: uppercase; }
        .chart-container { height: 300px; margin: 20px 0; }
        .recommendation { background: #e3f2fd; padding: 15px; margin: 10px 0; border-left: 4px solid #2196f3; border-radius: 4px; }
        .compliance-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .compliance-card { text-align: center; padding: 15px; border-radius: 8px; background: #f8f9fa; }
        .score-circle { width: 80px; height: 80px; border-radius: 50%; margin: 0 auto 10px; display: flex; align-items: center; justify-content: center; font-size: 1.2em; font-weight: bold; color: white; }
        .footer { text-align: center; padding: 20px; color: #666; border-top: 1px solid #eee; margin-top: 30px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Azaz-El Security Assessment Report</h1>
            <p>Comprehensive Security Analysis • Generated: {{ generation_time }}</p>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2>📊 Executive Summary</h2>
            <div class="metrics-grid">
                <div class="metric-card">
                    <div class="metric-value severity-{{ report.executive_summary.key_metrics.overall_risk_level.lower() }}">
                        {{ report.executive_summary.key_metrics.total_vulnerabilities }}
                    </div>
                    <div>Total Vulnerabilities</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value severity-critical">{{ report.executive_summary.key_metrics.critical_vulnerabilities }}</div>
                    <div>Critical Findings</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value severity-high">{{ report.executive_summary.key_metrics.high_risk_vulnerabilities }}</div>
                    <div>High Risk Findings</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{{ report.executive_summary.key_metrics.security_score }}/100</div>
                    <div>Security Score</div>
                </div>
            </div>
            
            <p style="font-size: 1.1em; margin-bottom: 20px;">{{ report.executive_summary.overview }}</p>
            
            <h3>🎯 Key Recommendations</h3>
            {% for rec in report.executive_summary.recommendations %}
            <div class="recommendation">{{ rec }}</div>
            {% endfor %}
        </div>

        <!-- Risk Analysis -->
        <div class="section">
            <h2>⚠️ Risk Analysis</h2>
            <div class="metrics-grid">
                <div class="metric-card">
                    <h4>Overall Risk Level</h4>
                    <div class="metric-value severity-{{ report.risk_analysis.overall_risk_level.lower() }}">
                        {{ report.risk_analysis.overall_risk_level }}
                    </div>
                </div>
                <div class="metric-card">
                    <h4>Total Risk Score</h4>
                    <div class="metric-value">{{ report.risk_analysis.total_risk_score }}</div>
                </div>
            </div>
            
            <h3>📈 Severity Distribution</h3>
            <div class="metrics-grid">
                {% for severity, count in report.risk_analysis.severity_distribution.items() %}
                <div class="metric-card">
                    <div class="metric-value severity-{{ severity.lower() }}">{{ count }}</div>
                    <div>{{ severity }}</div>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- Compliance Mapping -->
        <div class="section">
            <h2>📋 Compliance Status</h2>
            <div class="compliance-grid">
                {% for framework_id, framework in report.compliance_mapping.items() %}
                <div class="compliance-card">
                    <div class="score-circle" style="background-color: {% if framework.compliance_score >= 80 %}#28a745{% elif framework.compliance_score >= 60 %}#ffc107{% else %}#dc3545{% endif %};">
                        {{ framework.compliance_score }}%
                    </div>
                    <h4>{{ framework.name }}</h4>
                    <p>{{ framework.total_findings }} findings</p>
                </div>
                {% endfor %}
            </div>
        </div>

        <!-- Detailed Findings -->
        <div class="section">
            <h2>🔍 Detailed Findings</h2>
            <table class="findings-table">
                <thead>
                    <tr>
                        <th>ID</th>
                        <th>Title</th>
                        <th>Severity</th>
                        <th>Scanner</th>
                        <th>Target</th>
                        <th>Risk Score</th>
                    </tr>
                </thead>
                <tbody>
                    {% for finding in report.findings[:50] %}
                    <tr>
                        <td>{{ finding.id }}</td>
                        <td>{{ finding.title }}</td>
                        <td><span class="badge severity-{{ finding.severity.lower() }}">{{ finding.severity }}</span></td>
                        <td>{{ finding.scanner|title }}</td>
                        <td>{{ finding.target[:50] }}{% if finding.target|length > 50 %}...{% endif %}</td>
                        <td>{{ finding.risk_score }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <!-- Next Steps -->
        <div class="section">
            <h2>🚀 Next Steps</h2>
            <ol style="padding-left: 20px;">
                {% for step in report.executive_summary.next_steps %}
                <li style="margin: 10px 0;">{{ step }}</li>
                {% endfor %}
            </ol>
        </div>

        <div class="footer">
            <p>Report generated by Azaz-El v7.0.0-ULTIMATE • Advanced Automated Pentesting Framework</p>
            <p>For questions or support, contact your security team</p>
        </div>
    </div>
</body>
</html>
        '''
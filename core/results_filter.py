#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enhanced Results Filter for Azaz-El Framework
Advanced filtering with automated false positive detection and intelligent results processing
"""

import re
import json
import logging
from typing import Dict, Any, List, Optional, Set, Tuple
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
import hashlib

@dataclass
class FilterRule:
    """Represents a filtering rule"""
    rule_id: str
    name: str
    rule_type: str  # 'false_positive', 'severity_adjustment', 'category_filter'
    pattern: str
    action: str  # 'mark_fp', 'adjust_confidence', 'exclude', 'enhance'
    confidence_adjustment: float = 0.0
    enabled: bool = True
    description: str = ""
    
@dataclass
class FilterContext:
    """Context for filtering operations"""
    environment: str = 'production'  # production, staging, development, test
    target_type: str = 'web'  # web, api, infrastructure, mobile
    scan_type: str = 'general'  # general, compliance, penetration_test
    min_confidence: float = 0.3
    exclude_severities: List[str] = None
    exclude_categories: List[str] = None
    include_verified_only: bool = False
    auto_exclude_fps: bool = True
    
    def __post_init__(self):
        if self.exclude_severities is None:
            self.exclude_severities = []
        if self.exclude_categories is None:
            self.exclude_categories = []

class EnhancedResultsFilter:
    """Advanced results filtering with ML-based false positive detection"""
    
    def __init__(self, config: Dict[str, Any], logger: Optional[logging.Logger] = None):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        
        # Load filtering rules and patterns
        self.filter_rules = self._load_filter_rules()
        self.false_positive_patterns = self._load_false_positive_patterns()
        self.known_false_positives = self._load_known_false_positives()
        
        # Statistics tracking
        self.filter_stats = {
            'total_processed': 0,
            'false_positives_detected': 0,
            'confidence_adjustments': 0,
            'findings_excluded': 0,
            'duplicates_removed': 0
        }
    
    def filter_findings(self, findings: List[Any], context: FilterContext) -> List[Any]:
        """Apply comprehensive filtering to findings with performance monitoring"""
        start_time = datetime.now()
        filter_context = {
            "environment": context.environment,
            "target_type": context.target_type,
            "original_count": len(findings),
            "min_confidence": context.min_confidence
        }
        
        try:
            self.logger.info(f"🔍 Starting intelligent filtering of {len(findings)} findings")
            
            original_count = len(findings)
            filtered_findings = findings.copy()
            stage_stats = {}
            
            # Apply filtering stages with performance tracking
            stages = [
                ("false_positive_detection", self._apply_false_positive_detection),
                ("confidence_filtering", self._apply_confidence_filtering),
                ("severity_filtering", self._apply_severity_filtering),
                ("category_filtering", self._apply_category_filtering),
                ("duplicate_removal", self._apply_duplicate_removal),
                ("custom_rules", self._apply_custom_rules),
                ("enhancement", self._enhance_positive_findings)
            ]
            
            for stage_name, stage_func in stages:
                stage_start = datetime.now()
                before_count = len(filtered_findings)
                
                if stage_name in ["duplicate_removal"]:
                    filtered_findings = stage_func(filtered_findings)
                else:
                    filtered_findings = stage_func(filtered_findings, context)
                
                after_count = len(filtered_findings)
                stage_duration = (datetime.now() - stage_start).total_seconds()
                
                stage_stats[stage_name] = {
                    "before": before_count,
                    "after": after_count,
                    "removed": before_count - after_count,
                    "duration_ms": round(stage_duration * 1000, 2)
                }
                
                if before_count != after_count:
                    self.logger.debug(f"📊 {stage_name}: {before_count} → {after_count} findings "
                                    f"({stage_duration*1000:.1f}ms)")
            
            # Update statistics
            total_duration = (datetime.now() - start_time).total_seconds()
            self.filter_stats['total_processed'] += original_count
            self.filter_stats['findings_excluded'] += original_count - len(filtered_findings)
            
            # Enhanced logging with performance metrics
            filter_context.update({
                "final_count": len(filtered_findings),
                "total_removed": original_count - len(filtered_findings),
                "duration_ms": round(total_duration * 1000, 2),
                "stages": stage_stats
            })
            
            self.logger.info(f"✅ Filtering complete: {original_count} → {len(filtered_findings)} findings "
                           f"({total_duration*1000:.1f}ms)")
            
            if original_count - len(filtered_findings) > 0:
                self._log_filter_summary()
            
            return filtered_findings
            
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"❌ Filtering failed after {duration*1000:.1f}ms: {e}")
            return findings
    
    def _apply_false_positive_detection(self, findings: List[Any], context: FilterContext) -> List[Any]:
        """Detect and handle false positives"""
        filtered_findings = []
        fp_count = 0
        
        for finding in findings:
            is_fp, confidence_adjustment = self._is_likely_false_positive(finding, context)
            
            if is_fp and context.auto_exclude_fps:
                # Mark as false positive but don't exclude completely
                finding.false_positive = True
                finding.confidence *= 0.1  # Severely reduce confidence
                fp_count += 1
                self.logger.debug(f"Marked as false positive: {finding.title}")
            elif confidence_adjustment != 0:
                # Apply confidence adjustment
                finding.confidence = max(0.0, min(1.0, finding.confidence + confidence_adjustment))
                if hasattr(finding, 'metadata'):
                    finding.metadata['confidence_adjusted'] = True
                    finding.metadata['original_confidence'] = finding.confidence - confidence_adjustment
            
            filtered_findings.append(finding)
        
        self.filter_stats['false_positives_detected'] += fp_count
        self.logger.info(f"🚫 False positive detection: {fp_count} findings marked")
        
        return filtered_findings
    
    def _is_likely_false_positive(self, finding: Any, context: FilterContext) -> Tuple[bool, float]:
        """Determine if finding is likely a false positive"""
        
        # Check against known false positive patterns
        for pattern_data in self.false_positive_patterns:
            if self._matches_fp_pattern(finding, pattern_data, context):
                return True, -0.5
        
        # Check specific false positive indicators
        fp_indicators = [
            self._check_generic_error_pages(finding),
            self._check_development_artifacts(finding, context),
            self._check_low_impact_findings(finding),
            self._check_context_mismatch(finding, context),
            self._check_signature_based_fps(finding)
        ]
        
        fp_score = sum(fp_indicators)
        
        # If multiple indicators suggest FP, mark as false positive
        if fp_score >= 2:
            return True, -0.3
        elif fp_score == 1:
            return False, -0.2  # Reduce confidence but don't mark as FP
        
        return False, 0.0
    
    def _matches_fp_pattern(self, finding: Any, pattern_data: Dict[str, Any], context: FilterContext) -> bool:
        """Check if finding matches a false positive pattern"""
        try:
            pattern = pattern_data.get('pattern', '')
            pattern_context = pattern_data.get('context', '')
            pattern_severity = pattern_data.get('severity', '')
            
            # Check pattern match
            title_match = re.search(pattern, finding.title, re.IGNORECASE)
            desc_match = re.search(pattern, getattr(finding, 'description', ''), re.IGNORECASE)
            
            if not (title_match or desc_match):
                return False
            
            # Check context match
            if pattern_context and pattern_context != context.environment:
                return False
            
            # Check severity match
            if pattern_severity and pattern_severity != finding.severity.lower():
                return False
            
            return True
            
        except Exception as e:
            self.logger.debug(f"Pattern matching error: {e}")
            return False
    
    def _check_generic_error_pages(self, finding: Any) -> float:
        """Check for generic error page false positives"""
        error_indicators = [
            'error', '404', '403', '500', 'not found', 'access denied',
            'internal server error', 'bad request', 'unauthorized'
        ]
        
        text = f"{finding.title} {getattr(finding, 'description', '')}".lower()
        
        for indicator in error_indicators:
            if indicator in text:
                # Check if it's actually a meaningful security finding
                if any(term in text for term in ['injection', 'xss', 'csrf', 'lfi', 'rfi', 'sqli']):
                    return 0.0
                return 1.0
        
        return 0.0
    
    def _check_development_artifacts(self, finding: Any, context: FilterContext) -> float:
        """Check for development/testing artifacts"""
        if context.environment == 'production':
            dev_indicators = [
                'localhost', '127.0.0.1', 'test', 'debug', 'dev', 'staging',
                'example.com', 'sample', 'dummy', 'placeholder'
            ]
            
            text = f"{finding.title} {getattr(finding, 'description', '')} {getattr(finding, 'url', '')}".lower()
            
            for indicator in dev_indicators:
                if indicator in text:
                    return 1.0
        
        return 0.0
    
    def _check_low_impact_findings(self, finding: Any) -> float:
        """Check for low-impact findings that might be noise"""
        low_impact_patterns = [
            r'information disclosure.*server.*version',
            r'cookie.*without.*secure.*flag',
            r'missing.*security.*headers?',
            r'directory.*listing',
            r'banner.*grabbing'
        ]
        
        text = f"{finding.title} {getattr(finding, 'description', '')}".lower()
        
        for pattern in low_impact_patterns:
            if re.search(pattern, text):
                # Only consider as FP indicator if severity is info or low
                if finding.severity.lower() in ['info', 'low']:
                    return 0.5
        
        return 0.0
    
    def _check_context_mismatch(self, finding: Any, context: FilterContext) -> float:
        """Check for context mismatches"""
        
        # API-specific checks for web context
        if context.target_type == 'web':
            api_indicators = ['rest api', 'json api', 'graphql', 'soap', 'api endpoint']
            text = f"{finding.title} {getattr(finding, 'description', '')}".lower()
            
            if any(indicator in text for indicator in api_indicators):
                return 0.3
        
        # Web-specific checks for API context
        elif context.target_type == 'api':
            web_indicators = ['html', 'css', 'javascript', 'dom', 'browser']
            text = f"{finding.title} {getattr(finding, 'description', '')}".lower()
            
            if any(indicator in text for indicator in web_indicators):
                return 0.3
        
        return 0.0
    
    def _check_signature_based_fps(self, finding: Any) -> float:
        """Check against signature-based false positive database"""
        # Create a signature for the finding
        signature = self._create_finding_signature(finding)
        
        if signature in self.known_false_positives:
            fp_data = self.known_false_positives[signature]
            if fp_data.get('confidence', 0) > 0.8:
                return 1.0
            else:
                return 0.5
        
        return 0.0
    
    def _create_finding_signature(self, finding: Any) -> str:
        """Create a unique signature for a finding"""
        title = finding.title.lower().strip()
        severity = finding.severity.lower()
        url_pattern = re.sub(r'[0-9]+', 'X', getattr(finding, 'url', ''))
        
        signature_text = f"{title}|{severity}|{url_pattern}"
        return hashlib.md5(signature_text.encode()).hexdigest()
    
    def _apply_confidence_filtering(self, findings: List[Any], context: FilterContext) -> List[Any]:
        """Filter findings based on confidence thresholds"""
        filtered_findings = []
        excluded_count = 0
        
        for finding in findings:
            confidence = getattr(finding, 'confidence', 1.0)
            
            if confidence >= context.min_confidence:
                filtered_findings.append(finding)
            else:
                excluded_count += 1
                self.logger.debug(f"Excluded low confidence finding: {finding.title} (confidence: {confidence})")
        
        if excluded_count > 0:
            self.logger.info(f"🎯 Confidence filtering: excluded {excluded_count} low-confidence findings")
        
        return filtered_findings
    
    def _apply_severity_filtering(self, findings: List[Any], context: FilterContext) -> List[Any]:
        """Filter findings based on severity"""
        if not context.exclude_severities:
            return findings
        
        filtered_findings = []
        excluded_count = 0
        
        for finding in findings:
            if finding.severity.lower() not in [s.lower() for s in context.exclude_severities]:
                filtered_findings.append(finding)
            else:
                excluded_count += 1
                self.logger.debug(f"Excluded by severity: {finding.title} ({finding.severity})")
        
        if excluded_count > 0:
            self.logger.info(f"⚡ Severity filtering: excluded {excluded_count} findings")
        
        return filtered_findings
    
    def _apply_category_filtering(self, findings: List[Any], context: FilterContext) -> List[Any]:
        """Filter findings based on category"""
        if not context.exclude_categories:
            return findings
        
        filtered_findings = []
        excluded_count = 0
        
        for finding in findings:
            category = getattr(finding, 'category', 'general').lower()
            if category not in [c.lower() for c in context.exclude_categories]:
                filtered_findings.append(finding)
            else:
                excluded_count += 1
                self.logger.debug(f"Excluded by category: {finding.title} ({category})")
        
        if excluded_count > 0:
            self.logger.info(f"📂 Category filtering: excluded {excluded_count} findings")
        
        return filtered_findings
    
    def _apply_duplicate_removal(self, findings: List[Any]) -> List[Any]:
        """Remove duplicate findings using intelligent deduplication"""
        seen_signatures = set()
        unique_findings = []
        duplicates_removed = 0
        
        # Sort by confidence descending to keep highest confidence duplicates
        sorted_findings = sorted(findings, key=lambda f: getattr(f, 'confidence', 1.0), reverse=True)
        
        for finding in sorted_findings:
            signature = self._create_finding_signature(finding)
            
            if signature not in seen_signatures:
                seen_signatures.add(signature)
                unique_findings.append(finding)
            else:
                duplicates_removed += 1
                self.logger.debug(f"Removed duplicate: {finding.title}")
        
        self.filter_stats['duplicates_removed'] += duplicates_removed
        
        if duplicates_removed > 0:
            self.logger.info(f"🔄 Deduplication: removed {duplicates_removed} duplicate findings")
        
        return unique_findings
    
    def _apply_custom_rules(self, findings: List[Any], context: FilterContext) -> List[Any]:
        """Apply custom filtering rules"""
        filtered_findings = []
        rules_applied = 0
        
        for finding in findings:
            modified = False
            
            for rule in self.filter_rules:
                if not rule.enabled:
                    continue
                
                if self._rule_matches_finding(rule, finding, context):
                    if rule.action == 'mark_fp':
                        finding.false_positive = True
                        finding.confidence *= 0.1
                    elif rule.action == 'adjust_confidence':
                        finding.confidence = max(0.0, min(1.0, finding.confidence + rule.confidence_adjustment))
                    elif rule.action == 'exclude':
                        continue  # Skip this finding
                    elif rule.action == 'enhance':
                        finding.confidence = min(1.0, finding.confidence + 0.2)
                        if hasattr(finding, 'metadata'):
                            finding.metadata['enhanced'] = True
                    
                    modified = True
                    rules_applied += 1
            
            filtered_findings.append(finding)
        
        if rules_applied > 0:
            self.logger.info(f"📋 Custom rules: applied {rules_applied} rule modifications")
        
        return filtered_findings
    
    def _rule_matches_finding(self, rule: FilterRule, finding: Any, context: FilterContext) -> bool:
        """Check if a rule matches a finding"""
        try:
            pattern = rule.pattern
            
            # Create search text from finding
            search_text = f"{finding.title} {getattr(finding, 'description', '')} {getattr(finding, 'url', '')}"
            
            return bool(re.search(pattern, search_text, re.IGNORECASE))
            
        except Exception as e:
            self.logger.debug(f"Rule matching error: {e}")
            return False
    
    def _enhance_positive_findings(self, findings: List[Any], context: FilterContext) -> List[Any]:
        """Enhance and prioritize high-value positive findings"""
        high_value_indicators = [
            # Critical vulnerabilities
            r'sql injection|sqli',
            r'cross.?site.?scripting|xss',
            r'remote code execution|rce',
            r'local file inclusion|lfi',
            r'remote file inclusion|rfi',
            r'command injection',
            r'path traversal',
            r'authentication bypass',
            r'privilege escalation',
            r'directory traversal',
            
            # High-value information
            r'admin.?(panel|interface|console)',
            r'database.?(dump|backup|export)',
            r'configuration.?file',
            r'source.?code.?(disclosure|leak)',
            r'api.?key|secret.?key|access.?token',
            r'password.?(file|list|dump)',
            r'backup.?file',
            r'git.?(directory|folder)',
            r'\.env|environment.?file'
        ]
        
        enhanced_count = 0
        
        for finding in findings:
            text = f"{finding.title} {getattr(finding, 'description', '')}".lower()
            
            for pattern in high_value_indicators:
                if re.search(pattern, text):
                    # Enhance confidence and mark as verified
                    original_confidence = getattr(finding, 'confidence', 1.0)
                    finding.confidence = min(1.0, original_confidence + 0.2)
                    finding.verified = True
                    
                    if hasattr(finding, 'metadata'):
                        finding.metadata['high_value'] = True
                        finding.metadata['enhancement_reason'] = f"Matched pattern: {pattern}"
                    
                    enhanced_count += 1
                    self.logger.debug(f"Enhanced high-value finding: {finding.title}")
                    break
        
        if enhanced_count > 0:
            self.logger.info(f"⭐ Enhanced {enhanced_count} high-value findings")
        
        return findings
    
    def _load_filter_rules(self) -> List[FilterRule]:
        """Load filtering rules from configuration"""
        rules_file = Path("config/filter_rules.json")
        
        default_rules = [
            FilterRule(
                rule_id="fp_error_pages",
                name="Generic Error Pages",
                rule_type="false_positive",
                pattern=r"error.*page|404.*not.*found|403.*forbidden",
                action="mark_fp",
                description="Mark generic error pages as false positives"
            ),
            FilterRule(
                rule_id="enhance_sqli",
                name="SQL Injection Enhancement",
                rule_type="enhancement",
                pattern=r"sql.*injection|sqli",
                action="enhance",
                confidence_adjustment=0.2,
                description="Enhance SQL injection findings"
            ),
            FilterRule(
                rule_id="enhance_xss",
                name="XSS Enhancement",
                rule_type="enhancement",
                pattern=r"cross.*site.*scripting|xss",
                action="enhance",
                confidence_adjustment=0.2,
                description="Enhance XSS findings"
            )
        ]
        
        try:
            if rules_file.exists():
                with open(rules_file, 'r') as f:
                    rules_data = json.load(f)
                
                loaded_rules = []
                for rule_data in rules_data:
                    rule = FilterRule(**rule_data)
                    loaded_rules.append(rule)
                
                self.logger.info(f"Loaded {len(loaded_rules)} custom filter rules")
                return loaded_rules
            else:
                # Create default rules file
                rules_file.parent.mkdir(parents=True, exist_ok=True)
                with open(rules_file, 'w') as f:
                    json.dump([rule.__dict__ for rule in default_rules], f, indent=2)
                
                return default_rules
                
        except Exception as e:
            self.logger.warning(f"Failed to load filter rules: {e}, using defaults")
            return default_rules
    
    def _load_false_positive_patterns(self) -> List[Dict[str, Any]]:
        """Load false positive patterns"""
        return [
            {
                "pattern": r"server.*returned.*error.*404",
                "context": "",
                "severity": "",
                "description": "Generic 404 error responses"
            },
            {
                "pattern": r"cookie.*without.*httponly.*flag",
                "context": "development",
                "severity": "low",
                "description": "HTTPOnly flag missing in development"
            },
            {
                "pattern": r"missing.*x-frame-options.*header",
                "context": "",
                "severity": "info",
                "description": "Missing security headers on non-critical pages"
            },
            {
                "pattern": r"directory.*listing.*enabled",
                "context": "",
                "severity": "low",
                "description": "Directory listing on empty directories"
            },
            {
                "pattern": r"ssl.*certificate.*self.*signed",
                "context": "development",
                "severity": "medium",
                "description": "Self-signed certificates in development"
            }
        ]
    
    def _load_known_false_positives(self) -> Dict[str, Dict[str, Any]]:
        """Load known false positive signatures"""
        fp_file = Path("config/known_false_positives.json")
        
        try:
            if fp_file.exists():
                with open(fp_file, 'r') as f:
                    return json.load(f)
            else:
                return {}
        except Exception as e:
            self.logger.warning(f"Failed to load known false positives: {e}")
            return {}
    
    def _log_filter_summary(self):
        """Log filtering summary"""
        stats = self.filter_stats
        self.logger.info(f"📊 Filter Statistics:")
        self.logger.info(f"   Total processed: {stats['total_processed']}")
        self.logger.info(f"   False positives detected: {stats['false_positives_detected']}")
        self.logger.info(f"   Confidence adjustments: {stats['confidence_adjustments']}")
        self.logger.info(f"   Findings excluded: {stats['findings_excluded']}")
        self.logger.info(f"   Duplicates removed: {stats['duplicates_removed']}")
    
    def add_false_positive_signature(self, finding: Any, confidence: float = 1.0):
        """Add a finding signature to known false positives"""
        signature = self._create_finding_signature(finding)
        
        self.known_false_positives[signature] = {
            'title': finding.title,
            'severity': finding.severity,
            'confidence': confidence,
            'added_date': datetime.now().isoformat()
        }
        
        # Save to file
        fp_file = Path("config/known_false_positives.json")
        fp_file.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            with open(fp_file, 'w') as f:
                json.dump(self.known_false_positives, f, indent=2)
            
            self.logger.info(f"Added false positive signature: {finding.title}")
            
        except Exception as e:
            self.logger.error(f"Failed to save false positive signature: {e}")
    
    def get_filter_statistics(self) -> Dict[str, Any]:
        """Get filtering statistics"""
        return self.filter_stats.copy()
    
    def reset_statistics(self):
        """Reset filtering statistics"""
        self.filter_stats = {
            'total_processed': 0,
            'false_positives_detected': 0,
            'confidence_adjustments': 0,
            'findings_excluded': 0,
            'duplicates_removed': 0
        }
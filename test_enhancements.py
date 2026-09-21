"""
Test script to verify Ghostify enhancements
Tests SAST tools integration and vulnerability detection
"""

import os
import sys
import tempfile
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from app.core.logging import setup_logging, logger
from app.agentic.agents.code_scanner.sast_tools import SASTOrchestrator


def create_vulnerable_test_file(temp_dir: Path) -> Path:
    """Create a test file with intentional vulnerabilities"""
    
    vulnerable_code = '''
from fastapi import FastAPI
import os
import pickle

app = FastAPI()

# VULNERABILITY 1: Hardcoded secrets
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
PASSWORD = "admin123"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

# VULNERABILITY 2: SQL Injection
@app.get("/users/{user_id}")
def get_user(user_id: str):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return {"query": query}

# VULNERABILITY 3: Command Injection
@app.get("/ping/{host}")
def ping_host(host: str):
    result = os.system(f"ping {host}")
    return {"result": result}

# VULNERABILITY 4: Code Injection
@app.post("/eval")
def eval_code(code: str):
    result = eval(code)
    return {"result": result}

# VULNERABILITY 5: Insecure Deserialization
@app.post("/load")
def load_data(data: bytes):
    obj = pickle.loads(data)
    return {"loaded": str(obj)}

# VULNERABILITY 6: Missing Authentication
@app.delete("/admin/delete-all")
def delete_all():
    return {"message": "All data deleted"}

# VULNERABILITY 7: Another SQL injection
@app.get("/search")
def search(term: str):
    query = "SELECT * FROM products WHERE name = '%s'" % term
    return {"query": query}
'''
    
    test_file = temp_dir / "vulnerable_app.py"
    test_file.write_text(vulnerable_code)
    return test_file


def create_requirements_file(temp_dir: Path) -> Path:
    """Create a requirements file with vulnerable dependencies"""
    
    vulnerable_deps = '''
# Intentionally vulnerable versions for testing
django==2.2.0
flask==0.12.0
requests==2.6.0
'''
    
    req_file = temp_dir / "requirements.txt"
    req_file.write_text(vulnerable_deps)
    return req_file


def test_sast_tools():
    """Test SAST tools individually"""
    
    print("\n" + "="*80)
    print("🧪 TESTING SAST TOOLS")
    print("="*80)
    
    # Create temporary directory with vulnerable code
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test files
        print("\n📝 Creating test files with vulnerabilities...")
        test_file = create_vulnerable_test_file(temp_path)
        req_file = create_requirements_file(temp_path)
        print(f"   ✓ Created: {test_file.name}")
        print(f"   ✓ Created: {req_file.name}")
        
        # Initialize SAST orchestrator
        print("\n🔧 Initializing SAST Orchestrator...")
        orchestrator = SASTOrchestrator()
        
        # Run all scans
        print("\n🔍 Running SAST scans...")
        print("   This may take 30-60 seconds...")
        
        try:
            findings = orchestrator.run_all_scans(str(temp_path))
            
            print(f"\n✅ SAST scan completed!")
            print(f"   Total findings: {len(findings)}")
            
            # Categorize findings
            by_severity = {}
            by_tool = {}
            by_type = {}
            
            for finding in findings:
                # By severity
                severity = finding.severity
                by_severity[severity] = by_severity.get(severity, 0) + 1
                
                # By tool
                tool = finding.tool
                by_tool[tool] = by_tool.get(tool, 0) + 1
                
                # By type
                issue_type = finding.issue_type
                by_type[issue_type] = by_type.get(issue_type, 0) + 1
            
            # Print summary
            print("\n📊 Findings by Severity:")
            for severity in ["HIGH", "MEDIUM", "LOW"]:
                count = by_severity.get(severity, 0)
                if count > 0:
                    print(f"   {severity}: {count}")
            
            print("\n🔧 Findings by Tool:")
            for tool, count in sorted(by_tool.items()):
                print(f"   {tool}: {count}")
            
            print("\n🚨 Findings by Type:")
            for issue_type, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
                print(f"   {issue_type}: {count}")
            
            # Show top 10 findings
            print("\n🔍 Top 10 Findings:")
            for i, finding in enumerate(findings[:10], 1):
                print(f"\n   {i}. {finding.issue_type} ({finding.severity})")
                print(f"      File: {Path(finding.file_path).name}:{finding.line_number}")
                print(f"      Tool: {finding.tool}")
                print(f"      Description: {finding.description[:80]}...")
            
            # Verify expected vulnerabilities were found
            print("\n✅ Verification:")
            expected_types = [
                "HARDCODED_SECRET",
                "SQL_INJECTION", 
                "COMMAND_INJECTION",
                "CODE_INJECTION",
                "INSECURE_DESERIALIZATION"
            ]
            
            found_types = set(by_type.keys())
            for expected in expected_types:
                if expected in found_types:
                    print(f"   ✓ {expected} detected")
                else:
                    print(f"   ✗ {expected} NOT detected (may need tool installation)")
            
            return len(findings) > 0
            
        except Exception as e:
            print(f"\n❌ Error during SAST scan: {e}")
            import traceback
            traceback.print_exc()
            return False


def test_code_scanner_agent():
    """Test the enhanced Code Scanner Agent"""
    
    print("\n" + "="*80)
    print("🧪 TESTING CODE SCANNER AGENT")
    print("="*80)
    
    from app.agentic.agents.code_scanner.agent import code_scanner_agent
    
    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        
        # Create test files
        print("\n📝 Creating test files...")
        create_vulnerable_test_file(temp_path)
        create_requirements_file(temp_path)
        
        # Create mock state
        state = {
            "repo_path": str(temp_path)
        }
        
        print("\n🔍 Running Code Scanner Agent...")
        
        try:
            result = code_scanner_agent(state)
            
            print(f"\n✅ Code Scanner completed!")
            print(f"   Source files scanned: {len(result.get('source_files', []))}")
            print(f"   Endpoints found: {len(result.get('extracted_endpoints', []))}")
            print(f"   SAST findings: {len(result.get('sast_findings', []))}")
            
            # Show sample findings
            sast_findings = result.get('sast_findings', [])
            if sast_findings:
                print("\n🚨 Sample SAST Findings:")
                for i, finding in enumerate(sast_findings[:5], 1):
                    print(f"\n   {i}. {finding.get('issue_type')} ({finding.get('severity')})")
                    print(f"      File: {Path(finding.get('file_path', '')).name}:{finding.get('line_number')}")
                    print(f"      Tool: {finding.get('tool')}")
            
            return len(sast_findings) > 0
            
        except Exception as e:
            print(f"\n❌ Error in Code Scanner Agent: {e}")
            import traceback
            traceback.print_exc()
            return False


def check_dependencies():
    """Check if required SAST tools are installed"""
    
    print("\n" + "="*80)
    print("🔍 CHECKING DEPENDENCIES")
    print("="*80)
    
    tools = {
        "bandit": "bandit --version",
        "safety": "safety --version",
        "detect-secrets": "detect-secrets --version",
        "semgrep": "semgrep --version"
    }
    
    all_installed = True
    
    for tool, command in tools.items():
        try:
            import subprocess
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                print(f"   ✓ {tool} installed")
            else:
                print(f"   ✗ {tool} not working properly")
                all_installed = False
        except FileNotFoundError:
            print(f"   ✗ {tool} not installed")
            all_installed = False
        except Exception as e:
            print(f"   ? {tool} check failed: {e}")
    
    if not all_installed:
        print("\n⚠️  Some tools are missing. Install with:")
        print("   pip install -r requirements.txt")
    
    return all_installed


def main():
    """Run all tests"""
    
    print("\n" + "="*80)
    print("🚀 GHOSTIFY ENHANCEMENT TEST SUITE")
    print("="*80)
    
    # Setup logging
    setup_logging()
    
    # Check dependencies
    deps_ok = check_dependencies()
    
    # Run tests
    results = {}
    
    if deps_ok:
        results["SAST Tools"] = test_sast_tools()
        results["Code Scanner Agent"] = test_code_scanner_agent()
    else:
        print("\n⚠️  Skipping tests due to missing dependencies")
        print("   Install dependencies first: pip install -r requirements.txt")
        return False
    
    # Print final summary
    print("\n" + "="*80)
    print("📊 TEST SUMMARY")
    print("="*80)
    
    all_passed = True
    for test_name, passed in results.items():
        status = "✅ PASSED" if passed else "❌ FAILED"
        print(f"   {test_name}: {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "="*80)
    if all_passed:
        print("🎉 ALL TESTS PASSED!")
        print("="*80)
        print("\n✅ Your Ghostify enhancements are working correctly!")
        print("✅ SAST tools are detecting vulnerabilities")
        print("✅ Code Scanner Agent is functioning properly")
        print("\n📚 Next steps:")
        print("   1. Run: pip install -r requirements.txt (if not done)")
        print("   2. Test with real repositories")
        print("   3. Review QUICK_START.md for usage examples")
    else:
        print("⚠️  SOME TESTS FAILED")
        print("="*80)
        print("\n❌ Please check the error messages above")
        print("❌ Ensure all dependencies are installed")
        print("\n📚 Troubleshooting:")
        print("   1. Install dependencies: pip install -r requirements.txt")
        print("   2. Check logs: tail -f logs/agent.log")
        print("   3. Review QUICK_START.md for help")
    
    return all_passed


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

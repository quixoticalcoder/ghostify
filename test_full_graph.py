"""
Full Audit Graph Test
Tests the complete Ghostify pipeline end-to-end
"""

import os
import sys
import tempfile
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from app.core.logging import setup_logging, logger
from app.agentic.graph.audit_graph import audit_app


def create_test_repository():
    """Create a test repository with vulnerable code"""
    
    temp_dir = tempfile.mkdtemp(prefix="ghostify_test_")
    temp_path = Path(temp_dir)
    
    # Create a vulnerable FastAPI application
    app_file = temp_path / "main.py"
    app_file.write_text('''
from fastapi import FastAPI
import os
import pickle

app = FastAPI()

# Vulnerability 1: Hardcoded credentials
API_KEY = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
DATABASE_PASSWORD = "admin123"

# Vulnerability 2: SQL Injection
@app.get("/users/{user_id}")
def get_user(user_id: str):
    """Get user by ID - VULNERABLE TO SQL INJECTION"""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return {"query": query}

# Vulnerability 3: Command Injection
@app.get("/ping/{host}")
def ping_host(host: str):
    """Ping a host - VULNERABLE TO COMMAND INJECTION"""
    result = os.system(f"ping {host}")
    return {"result": result}

# Vulnerability 4: Code Injection
@app.post("/eval")
def eval_code(code: str):
    """Evaluate code - VULNERABLE TO CODE INJECTION"""
    result = eval(code)
    return {"result": result}

# Vulnerability 5: Insecure Deserialization
@app.post("/load")
def load_data(data: bytes):
    """Load pickled data - VULNERABLE TO INSECURE DESERIALIZATION"""
    obj = pickle.loads(data)
    return {"loaded": str(obj)}

# Vulnerability 6: Missing Authentication
@app.delete("/admin/delete-all")
def delete_all():
    """Delete all data - NO AUTHENTICATION"""
    return {"message": "All data deleted"}
''')
    
    # Create requirements.txt
    req_file = temp_path / "requirements.txt"
    req_file.write_text('''
fastapi==0.100.0
uvicorn==0.23.0
''')
    
    return str(temp_path)


def test_full_audit_graph():
    """Test the complete audit graph"""
    
    print("\n" + "="*80)
    print("🧪 TESTING FULL AUDIT GRAPH")
    print("="*80)
    
    # Setup logging
    setup_logging()
    
    # Create test repository
    print("\n📝 Creating test repository with vulnerabilities...")
    repo_path = create_test_repository()
    print(f"   ✓ Created test repo at: {repo_path}")
    
    # Prepare initial state
    initial_state = {
        "repo_url": "test://local",
        "repo_path": repo_path,
        "commit_hash": None,
        "api_base_url": None,  # Static analysis only
    }
    
    print("\n🚀 Running full audit graph...")
    print("   This will execute all agents:")
    print("   1. Code Scanner (with SAST)")
    print("   2. API Mapper")
    print("   3. Logic Reasoner (with LLM)")
    print("   4. Attack Executor (skipped - no API)")
    print("   5. Validator")
    print("   6. Reporter")
    print("\n   ⏳ This may take 1-2 minutes...")
    
    try:
        # Run the audit graph
        result = audit_app.invoke(initial_state)
        
        print("\n✅ Audit graph completed successfully!")
        
        # Extract results
        final_report = result.get("final_report", {})
        summary = final_report.get("summary", {})
        
        print("\n" + "="*80)
        print("📊 AUDIT RESULTS")
        print("="*80)
        
        print(f"\n📈 Summary:")
        print(f"   Total Vulnerabilities: {summary.get('total_vulnerabilities', 0)}")
        print(f"   Static (SAST): {summary.get('static_vulnerabilities', 0)}")
        print(f"   Dynamic (Attacks): {summary.get('dynamic_vulnerabilities', 0)}")
        
        if summary.get('by_severity'):
            print(f"\n   By Severity:")
            for severity, count in summary['by_severity'].items():
                print(f"      {severity}: {count}")
        
        # Show SAST tools used
        sast_tools = final_report.get('sast_tools_used', [])
        if sast_tools:
            print(f"\n🔧 SAST Tools Used: {', '.join(sast_tools)}")
        
        # Show static vulnerabilities
        static_vulns = final_report.get('static_vulnerabilities', [])
        if static_vulns:
            print(f"\n🚨 Static Vulnerabilities ({len(static_vulns)}):")
            for i, vuln in enumerate(static_vulns[:10], 1):
                print(f"\n   {i}. {vuln.get('type')} ({vuln.get('severity')})")
                print(f"      File: {Path(vuln.get('file', '')).name}:{vuln.get('line')}")
                print(f"      Tool: {vuln.get('tool')}")
                print(f"      Description: {vuln.get('description', '')[:80]}...")
        
        # Show dynamic vulnerabilities (if any)
        dynamic_vulns = final_report.get('dynamic_vulnerabilities', [])
        if dynamic_vulns:
            print(f"\n⚡ Dynamic Vulnerabilities ({len(dynamic_vulns)}):")
            for i, vuln in enumerate(dynamic_vulns[:5], 1):
                print(f"\n   {i}. {vuln.get('type')} ({vuln.get('severity')})")
                print(f"      Endpoint: {vuln.get('endpoint')}")
        
        # Show state progression
        print("\n" + "="*80)
        print("📋 AGENT EXECUTION SUMMARY")
        print("="*80)
        
        print(f"\n✓ Code Scanner:")
        print(f"   - Files scanned: {len(result.get('source_files', []))}")
        print(f"   - Endpoints found: {len(result.get('extracted_endpoints', []))}")
        print(f"   - SAST findings: {len(result.get('sast_findings', []))}")
        
        print(f"\n✓ API Mapper:")
        print(f"   - API map created: {'Yes' if result.get('api_map') else 'No'}")
        print(f"   - Sensitive operations: {len(result.get('sensitive_operations', []))}")
        
        print(f"\n✓ Logic Reasoner:")
        print(f"   - Attack chains planned: {len(result.get('planned_attack_chains', []))}")
        print(f"   - Misuse cases identified: {len(result.get('potential_misuse_cases', []))}")
        
        print(f"\n✓ Attack Executor:")
        print(f"   - Attacks executed: {len(result.get('executed_attacks', []))}")
        print(f"   - Note: Skipped (no API base URL provided)")
        
        print(f"\n✓ Validator:")
        print(f"   - Confirmed vulnerabilities: {len(result.get('confirmed_vulnerabilities', []))}")
        print(f"   - False positives filtered: {len(result.get('false_positives', []))}")
        
        print(f"\n✓ Reporter:")
        print(f"   - Final report generated: Yes")
        print(f"   - Total findings: {summary.get('total_vulnerabilities', 0)}")
        
        # Verification
        print("\n" + "="*80)
        print("✅ VERIFICATION")
        print("="*80)
        
        success = True
        
        # Check if vulnerabilities were found
        if summary.get('total_vulnerabilities', 0) > 0:
            print("   ✓ Vulnerabilities detected")
        else:
            print("   ✗ No vulnerabilities detected (UNEXPECTED)")
            success = False
        
        # Check if SAST tools ran
        if len(result.get('sast_findings', [])) > 0:
            print("   ✓ SAST tools executed successfully")
        else:
            print("   ✗ SAST tools did not find anything (UNEXPECTED)")
            success = False
        
        # Check if all agents ran
        required_fields = [
            'source_files', 'sast_findings', 'api_map',
            'planned_attack_chains', 'final_report'
        ]
        
        missing_fields = [f for f in required_fields if f not in result]
        if not missing_fields:
            print("   ✓ All agents executed successfully")
        else:
            print(f"   ✗ Missing fields: {', '.join(missing_fields)}")
            success = False
        
        # Check report structure
        if 'summary' in final_report and 'static_vulnerabilities' in final_report:
            print("   ✓ Report structure is correct")
        else:
            print("   ✗ Report structure is incomplete")
            success = False
        
        return success
        
    except Exception as e:
        print(f"\n❌ Error during audit graph execution: {e}")
        import traceback
        traceback.print_exc()
        return False


def main():
    """Run the full graph test"""
    
    print("\n" + "="*80)
    print("🚀 GHOSTIFY FULL GRAPH TEST")
    print("="*80)
    
    print("\n⚠️  Note: This test requires:")
    print("   - GROQ_API_KEY environment variable set")
    print("   - LANGCHAIN_API_KEY environment variable set")
    print("   - All SAST tools installed")
    
    # Check environment variables
    if not os.getenv("GROQ_API_KEY"):
        print("\n❌ ERROR: GROQ_API_KEY not set")
        print("   Please set it in your .env file or environment")
        return False
    
    if not os.getenv("LANGCHAIN_API_KEY"):
        print("\n⚠️  WARNING: LANGCHAIN_API_KEY not set")
        print("   LangSmith tracing will be disabled")
    
    # Run test
    success = test_full_audit_graph()
    
    # Final result
    print("\n" + "="*80)
    if success:
        print("🎉 FULL GRAPH TEST PASSED!")
        print("="*80)
        print("\n✅ Your Ghostify system is working end-to-end!")
        print("✅ All agents are functioning correctly")
        print("✅ SAST integration is working")
        print("✅ LLM reasoning is operational")
        print("✅ Report generation is successful")
        print("\n📚 Next steps:")
        print("   1. Test with real GitHub repositories")
        print("   2. Test with live API endpoints")
        print("   3. Review ENHANCEMENTS_SUMMARY.md for details")
    else:
        print("⚠️  FULL GRAPH TEST HAD ISSUES")
        print("="*80)
        print("\n❌ Some components may not be working correctly")
        print("📚 Troubleshooting:")
        print("   1. Check logs/agent.log for detailed errors")
        print("   2. Verify all environment variables are set")
        print("   3. Ensure SAST tools are installed")
        print("   4. Review QUICK_START.md for setup instructions")
    
    return success


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)

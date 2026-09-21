#!/usr/bin/env python3
"""
Test script for Gemini CLI integration
Tests critical path: localhost detection, code fixer agent, and report generation
"""

import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

print("="*80)
print("🧪 Testing Gemini CLI Integration - Critical Path")
print("="*80)

# Test 1: Import all new modules
print("\n📦 Test 1: Importing new modules...")
try:
    from backend.app.agentic.agents.code_fixer.agent import code_fixer_agent
    from backend.app.services.localhost_detector import detect_localhost_urls, is_port_open
    print("✅ All imports successful")
except Exception as e:
    print(f"❌ Import failed: {e}")
    sys.exit(1)

# Test 2: Localhost detection
print("\n🔍 Test 2: Testing localhost detection...")
try:
    # Test port checking
    is_open = is_port_open("localhost", 80, timeout=0.1)
    print(f"   Port 80 check: {'Open' if is_open else 'Closed'}")
    
    # Test localhost detection (quick scan)
    urls = detect_localhost_urls([3000, 5000, 8000])
    print(f"✅ Localhost detection works")
    print(f"   Found {len(urls)} active server(s): {urls}")
except Exception as e:
    print(f"❌ Localhost detection failed: {e}")
    import traceback
    traceback.print_exc()

# Test 3: Code Fixer Agent with mock data
print("\n🔧 Test 3: Testing Code Fixer Agent...")
try:
    from backend.app.agentic.state.audit_state import SecurityAuditState
    
    # Create mock state with vulnerabilities
    mock_state: SecurityAuditState = {
        "repo_path": str(Path(__file__).parent),
        "confirmed_vulnerabilities": [],
        "static_vulnerabilities": [
            {
                "type": "TEST_VULNERABILITY",
                "severity": "HIGH",
                "file": __file__,
                "line": 1,
                "description": "Test vulnerability for testing",
                "code_snippet": "print('test')",
                "tool": "test_tool",
                "category": "STATIC_ANALYSIS"
            }
        ]
    }
    
    print("   Running code_fixer_agent with mock data...")
    result = code_fixer_agent(mock_state)
    
    fixes = result.get("vulnerability_fixes", [])
    print(f"✅ Code Fixer Agent executed")
    print(f"   Generated {len(fixes)} fix(es)")
    
    if fixes:
        print(f"   Sample fix:")
        print(f"     - Type: {fixes[0].get('vulnerability_type')}")
        print(f"     - File: {fixes[0].get('file')}")
        print(f"     - Has fixed code: {bool(fixes[0].get('fixed_code'))}")
    else:
        print("   ⚠️  No fixes generated (Gemini CLI may not be installed)")
        
except Exception as e:
    print(f"❌ Code Fixer Agent failed: {e}")
    import traceback
    traceback.print_exc()

# Test 4: Graph integration
print("\n🕸️  Test 4: Testing graph integration...")
try:
    from backend.app.agentic.graph.audit_graph import audit_app
    from backend.app.core.constants import CODE_FIXER_AGENT
    
    # Check if code fixer is in the graph
    graph_dict = audit_app.get_graph().to_json()
    
    print(f"✅ Graph compiled successfully")
    print(f"   Code Fixer Agent in graph: {CODE_FIXER_AGENT in str(graph_dict)}")
    
except Exception as e:
    print(f"❌ Graph integration failed: {e}")
    import traceback
    traceback.print_exc()

# Test 5: Enhanced CLI imports
print("\n🖥️  Test 5: Testing enhanced CLI...")
try:
    # Check if the file exists and is importable
    cli_file = Path(__file__).parent / "run_audit_with_fixes.py"
    
    if cli_file.exists():
        print(f"✅ Enhanced CLI file exists: {cli_file}")
        
        # Try to parse it (syntax check)
        with open(cli_file, 'r', encoding='utf-8') as f:
            code = f.read()
            compile(code, str(cli_file), 'exec')
        print(f"✅ Enhanced CLI syntax is valid")
    else:
        print(f"❌ Enhanced CLI file not found")
        
except Exception as e:
    print(f"❌ Enhanced CLI check failed: {e}")
    import traceback
    traceback.print_exc()

# Test 6: Check Gemini CLI availability
print("\n🤖 Test 6: Checking Gemini CLI availability...")
try:
    import subprocess
    
    result = subprocess.run(
        ["gemini", "--version"],
        capture_output=True,
        timeout=5,
        text=True
    )
    
    if result.returncode == 0:
        print(f"✅ Gemini CLI is installed")
        print(f"   Version info: {result.stdout.strip()}")
    else:
        print(f"⚠️  Gemini CLI found but returned error")
        print(f"   Error: {result.stderr}")
        
except FileNotFoundError:
    print(f"⚠️  Gemini CLI not found")
    print(f"   Install with: npm install -g @google/generative-ai-cli")
except subprocess.TimeoutExpired:
    print(f"⚠️  Gemini CLI timeout")
except Exception as e:
    print(f"⚠️  Could not check Gemini CLI: {e}")

# Summary
print("\n" + "="*80)
print("📊 TEST SUMMARY")
print("="*80)
print("""
✅ Critical components tested:
   - Module imports
   - Localhost detection
   - Code Fixer Agent
   - Graph integration
   - Enhanced CLI syntax
   - Gemini CLI availability

⚠️  Note: Full end-to-end testing requires:
   - Gemini CLI installed (npm install -g @google/generative-ai-cli)
   - GOOGLE_API_KEY environment variable set
   - A test repository to audit

🚀 Next steps:
   1. Install Gemini CLI if not already installed
   2. Set GOOGLE_API_KEY environment variable
   3. Run: python run_audit_with_fixes.py <repo-url>
""")
print("="*80)

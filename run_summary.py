#!/usr/bin/env python3
"""
Ghostify CLI - Summary-Only Mode

This mode:
- Runs the full security audit pipeline
- Does NOT perform code fixing
- Does NOT modify any files
- Uses LLM ONLY as a report generator (no file access)
- Generates human-readable security summary

Usage:
    python run_summary.py <repo_url>

Examples:
    python run_summary.py https://github.com/user/repo
"""

import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent / "backend"))

from backend.app.agentic.graph.audit_graph import summary_app
from backend.app.core.logging import setup_logging, logger
from backend.app.services.github import GitHubService
from backend.app.services.localhost_detector import prompt_user_for_localhost


def print_banner():
    """Print Ghostify banner"""
    print("\n" + "="*80)
    print("👻 GHOSTIFY - Security Summary Mode")
    print("="*80)


def print_usage():
    """Print usage instructions"""
    print("\nUsage: python run_summary.py <repo_url>")
    print("\nExamples:")
    print("  python run_summary.py https://github.com/user/repo")
    print()
    print("Features:")
    print("  ✓ Auto-detects running localhost servers")
    print("  ✓ Performs comprehensive security audit")
    print("  ✓ Generates human-readable security summary")
    print("  ✓ NO code fixes or file modifications")
    print()
    print("Required:")
    print("  - GOOGLE_API_KEY environment variable")
    print()


def check_environment():
    """Check if required environment variables are set"""
    if not os.getenv("GOOGLE_API_KEY"):
        print("\n❌ ERROR: GOOGLE_API_KEY environment variable not set!")
        print("\nPlease set it in your .env file or environment:")
        print("  export GOOGLE_API_KEY='your-key-here'")
        print("\nGet your API key at: https://aistudio.google.com/app/apikey")
        return False
    return True


def main():
    """Main CLI function"""
    
    print_banner()
    
    # Check arguments
    if len(sys.argv) < 2:
        print_usage()
        sys.exit(1)
    
    # Check environment
    if not check_environment():
        sys.exit(1)
    
    # Setup logging
    setup_logging()
    
    # Get repo URL
    repo_url = sys.argv[1]
    
    if not repo_url.startswith("http"):
        print(f"\n❌ ERROR: Please provide a GitHub repository URL")
        print(f"   Got: {repo_url}")
        print_usage()
        sys.exit(1)
    
    print(f"\n📦 Target Repository: {repo_url}")
    
    # Auto-detect localhost
    print(f"\n🔍 Detecting running localhost servers...")
    api_url = prompt_user_for_localhost()
    
    if api_url:
        print(f"\n✓ Using API URL: {api_url}")
        print(f"   Mode: Static + Dynamic Analysis")
    else:
        print(f"\n✓ No API URL selected")
        print(f"   Mode: Static Analysis Only")
    
    print(f"\n⏳ Starting security audit...")
    print(f"   This may take 2-3 minutes...")
    print()
    
    github_service = None
    
    try:
        # Clone repository
        print(f"\n📥 Cloning repository...")
        github_service = GitHubService(
            repo_url=repo_url,
            commit_hash=None
        )
        repo_path = github_service.clone()
        print(f"   ✓ Cloned to: {repo_path}")
        
        # Run audit in summary mode (NO code fixing)
        print(f"\n🤖 Running multi-agent security audit...")
        result = summary_app.invoke({
            "repo_url": repo_url,
            "repo_path": repo_path,
            "commit_hash": None,
            "api_base_url": api_url
        })
        
        # Display audit results
        print("\n" + "="*80)
        print("📊 AUDIT RESULTS")
        print("="*80)
        
        report = result["final_report"]
        summary_text = result.get("security_summary", "")
        
        summary_data = report["summary"]
        
        print(f"\n📈 Summary:")
        print(f"   Total Vulnerabilities: {summary_data['total_vulnerabilities']}")
        print(f"   Static (SAST): {summary_data['static_vulnerabilities']}")
        print(f"   Dynamic (Attacks): {summary_data['dynamic_vulnerabilities']}")
        
        if summary_data.get('by_severity'):
            print(f"\n   By Severity:")
            for severity in ['HIGH', 'MEDIUM', 'LOW']:
                count = summary_data['by_severity'].get(severity, 0)
                if count > 0:
                    emoji = "🔴" if severity == "HIGH" else "🟡" if severity == "MEDIUM" else "🟢"
                    print(f"      {emoji} {severity}: {count}")
        
        # Display security summary
        if summary_text:
            print("\n" + "="*80)
            print("📋 SECURITY SUMMARY")
            print("="*80)
            print()
            print(summary_text)
            print()
            print("="*80)
        
        # Save reports
        output_dir = Path("./reports")
        output_dir.mkdir(exist_ok=True)
        
        import json
        from datetime import datetime
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Save audit report (JSON)
        report_file = output_dir / f"audit_report_{timestamp}.json"
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n📄 Audit report saved to: {report_file}")
        
        # Save security summary (TXT)
        if summary_text:
            summary_file = output_dir / f"security_summary_{timestamp}.txt"
            with open(summary_file, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("GHOSTIFY - SECURITY SUMMARY\n")
                f.write("="*80 + "\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Repository: {repo_url}\n")
                f.write(f"Application URL: {api_url if api_url else 'Static analysis only'}\n\n")
                f.write("="*80 + "\n\n")
                f.write(summary_text)
                f.write("\n\n" + "="*80 + "\n")
            
            print(f"📋 Security summary saved to: {summary_file}")
        
        # Final message
        print("\n" + "="*80)
        if summary_data['total_vulnerabilities'] == 0:
            print("✅ No vulnerabilities found! Your code looks secure.")
        else:
            print(f"✅ Audit complete!")
            print(f"   Found {summary_data['total_vulnerabilities']} vulnerabilities")
            print(f"   Generated human-readable security summary")
            print(f"\n   Review the reports above for details.")
        print("="*80)
        print()
        
        # Cleanup
        if github_service:
            github_service.cleanup()
            print(f"🧹 Cleaned up temporary files\n")
        
        return 0 if summary_data['total_vulnerabilities'] == 0 else 1
        
    except KeyboardInterrupt:
        print("\n\n⚠️  Audit interrupted by user")
        if github_service:
            github_service.cleanup()
        return 130
        
    except Exception as e:
        print(f"\n❌ ERROR: Audit failed!")
        print(f"   {str(e)}")
        logger.exception("Audit failed")
        print(f"\n📋 Check logs for details: logs/agent.log")
        
        if github_service:
            github_service.cleanup()
        
        return 1


if __name__ == "__main__":
    sys.exit(main())

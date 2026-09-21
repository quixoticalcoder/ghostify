"""
Localhost Detector - Auto-detect running localhost servers
"""
import socket
import requests
from typing import List, Optional
from app.core.logging import logger


def detect_localhost_urls(ports: List[int] = None) -> List[str]:
    """
    Detect running localhost servers on common ports.
    
    Args:
        ports: List of ports to check. If None, checks common ports.
        
    Returns:
        List of active localhost URLs
    """
    
    if ports is None:
        # Common development ports
        ports = [
            3000,  # React, Next.js
            3001,  # Alternative React
            4200,  # Angular
            5000,  # Flask
            5173,  # Vite
            8000,  # Django, FastAPI
            8080,  # Alternative HTTP
            8081,  # Alternative HTTP
            8888,  # Jupyter
            9000,  # Alternative
        ]
    
    active_urls = []
    
    logger.info(f"Scanning for localhost servers on {len(ports)} ports...")
    
    for port in ports:
        if is_port_open("localhost", port):
            url = f"http://localhost:{port}"
            if is_http_server(url):
                active_urls.append(url)
                logger.info(f"✓ Found active server: {url}")
    
    if not active_urls:
        logger.warning("No active localhost servers detected")
    else:
        logger.info(f"Detected {len(active_urls)} active localhost server(s)")
    
    return active_urls


def is_port_open(host: str, port: int, timeout: float = 0.5) -> bool:
    """
    Check if a port is open on the given host.
    
    Args:
        host: Hostname to check
        port: Port number
        timeout: Connection timeout in seconds
        
    Returns:
        True if port is open, False otherwise
    """
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def is_http_server(url: str, timeout: float = 2.0) -> bool:
    """
    Check if the URL responds to HTTP requests.
    
    Args:
        url: URL to check
        timeout: Request timeout in seconds
        
    Returns:
        True if URL responds, False otherwise
    """
    
    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        return response.status_code < 500
    except Exception:
        return False


def get_best_localhost_url(urls: List[str] = None) -> Optional[str]:
    """
    Get the best localhost URL from detected servers.
    Prioritizes common development ports.
    
    Args:
        urls: List of URLs to choose from. If None, auto-detects.
        
    Returns:
        Best localhost URL, or None if none found
    """
    
    if urls is None:
        urls = detect_localhost_urls()
    
    if not urls:
        return None
    
    # Priority order for common ports
    priority_ports = [3000, 5000, 8000, 4200, 5173, 8080]
    
    for port in priority_ports:
        for url in urls:
            if f":{port}" in url:
                return url
    
    # Return first URL if no priority match
    return urls[0]


def prompt_user_for_localhost() -> Optional[str]:
    """
    Prompt user to select or enter a localhost URL.
    
    Returns:
        Selected localhost URL, or None if skipped
    """
    
    detected_urls = detect_localhost_urls()
    
    if not detected_urls:
        print("\n⚠️  No localhost servers detected.")
        print("Please start your application and try again, or enter URL manually.")
        
        manual_url = input("\nEnter localhost URL (or press Enter to skip): ").strip()
        
        if manual_url:
            if not manual_url.startswith("http"):
                manual_url = f"http://{manual_url}"
            return manual_url
        
        return None
    
    print(f"\n🔍 Detected {len(detected_urls)} localhost server(s):")
    for idx, url in enumerate(detected_urls, 1):
        print(f"  {idx}. {url}")
    
    print(f"  {len(detected_urls) + 1}. Enter custom URL")
    print(f"  {len(detected_urls) + 2}. Skip (static analysis only)")
    
    while True:
        try:
            choice = input(f"\nSelect option (1-{len(detected_urls) + 2}): ").strip()
            
            if not choice:
                return detected_urls[0]  # Default to first
            
            choice_num = int(choice)
            
            if 1 <= choice_num <= len(detected_urls):
                return detected_urls[choice_num - 1]
            elif choice_num == len(detected_urls) + 1:
                manual_url = input("Enter localhost URL: ").strip()
                if not manual_url.startswith("http"):
                    manual_url = f"http://{manual_url}"
                return manual_url
            elif choice_num == len(detected_urls) + 2:
                return None
            else:
                print("Invalid choice. Please try again.")
                
        except ValueError:
            print("Invalid input. Please enter a number.")
        except KeyboardInterrupt:
            print("\n\nSkipping localhost detection.")
            return None

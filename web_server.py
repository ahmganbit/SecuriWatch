#!/usr/bin/env python3
"""
SecurityWatch Pro - Web Server Launcher
Launch the beautiful web dashboard for SecurityWatch Pro
"""

import sys
import argparse
from pathlib import Path

# Add the securitywatch package to the path
sys.path.insert(0, str(Path(__file__).parent))

from securitywatch.web.app import run_web_server


def main():
    """Main web server launcher"""
    parser = argparse.ArgumentParser(
        description="SecurityWatch Pro Web Dashboard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s                          Start web server on localhost:5000
  %(prog)s --host 0.0.0.0           Start server accessible from network
  %(prog)s --port 8080              Start server on port 8080
  %(prog)s --debug                  Start in debug mode
        """
    )
    
    parser.add_argument('--host', default='127.0.0.1',
                       help='Host to bind to (default: 127.0.0.1)')
    parser.add_argument('--port', type=int, default=5000,
                       help='Port to bind to (default: 5000)')
    parser.add_argument('--debug', action='store_true',
                       help='Run in debug mode')
    
    args = parser.parse_args()
    
    print("🛡️ SecurityWatch Pro - Web Dashboard")
    print("=" * 50)
    print(f"🌐 Starting web server...")
    print(f"🔗 URL: http://{args.host}:{args.port}")
    print(f"🎯 Debug mode: {'Enabled' if args.debug else 'Disabled'}")
    print("=" * 50)
    print()
    print("📊 Features available:")
    print("  • Real-time threat monitoring dashboard")
    print("  • Interactive charts and graphs")
    print("  • Live threat feed with animations")
    print("  • Configuration management")
    print("  • Professional reporting")
    print("  • Mobile-responsive design")
    print()
    print("🚀 Press Ctrl+C to stop the server")
    print()
    
    try:
        run_web_server(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        print("\n🛑 Web server stopped by user")
    except Exception as e:
        print(f"❌ Error starting web server: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

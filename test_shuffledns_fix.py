#!/usr/bin/env python3
"""
Test script to verify shuffledns resolver file creation logic
"""

import sys
from pathlib import Path

# Add the project directory to path so we can import moloch
sys.path.append(str(Path(__file__).parent))

from moloch import run_subdomain_discovery, load_config
import tempfile

def test_shuffledns_resolver_creation():
    """Test that shuffledns resolver file is created correctly"""
    
    # Create a temporary output directory
    with tempfile.TemporaryDirectory() as temp_dir:
        output_dir = Path(temp_dir)
        config = load_config()
        
        # Mock target
        target = "test.example.com"
        
        print(f"Testing shuffledns resolver file creation...")
        print(f"Output directory: {output_dir}")
        
        # Run subdomain discovery (will create resolver file even if shuffledns isn't installed)
        try:
            run_subdomain_discovery(target, output_dir, config)
            
            # Check if resolver file was created
            resolver_file = output_dir / "resolvers.txt"
            
            if resolver_file.exists():
                print(f"✅ Resolver file created: {resolver_file}")
                
                # Read and display contents
                with open(resolver_file, 'r') as f:
                    contents = f.read()
                print(f"📄 Resolver file contents:\n{contents}")
                
                # Verify it contains expected DNS servers
                lines = contents.strip().split('\n')
                expected_resolvers = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1"]
                
                if all(resolver in lines for resolver in expected_resolvers):
                    print("✅ All expected DNS resolvers found in file")
                    return True
                else:
                    print("❌ Not all expected DNS resolvers found")
                    return False
            else:
                print("❌ Resolver file was not created")
                return False
                
        except Exception as e:
            print(f"❌ Error during test: {e}")
            return False

if __name__ == "__main__":
    success = test_shuffledns_resolver_creation()
    sys.exit(0 if success else 1)
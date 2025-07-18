#!/bin/bash

# Leegion Framework Release Script
# This script automates the GitHub release process

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    # Check if gh CLI is installed
    if ! command -v gh &> /dev/null; then
        print_error "GitHub CLI (gh) is not installed. Please install it first."
        print_status "Installation: https://cli.github.com/"
        exit 1
    fi
    
    # Check if user is authenticated
    if ! gh auth status &> /dev/null; then
        print_error "Not authenticated with GitHub CLI. Please run 'gh auth login' first."
        exit 1
    fi
    
    # Check if we're in a git repository
    if ! git rev-parse --git-dir > /dev/null 2>&1; then
        print_error "Not in a git repository."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Read version from config
get_version() {
    print_status "Reading version from config..."
    
    if [ -f "pyproject.toml" ]; then
        VERSION=$(python3 -c "import toml; print(toml.load('pyproject.toml')['project']['version'])")
    elif [ -f "config/config.json" ]; then
        VERSION=$(python3 -c "import json; print(json.load(open('config/config.json')).get('version', '2.0.0'))")
    else
        print_error "Could not find version in pyproject.toml or config/config.json"
        exit 1
    fi
    
    print_success "Version: $VERSION"
}

# Check if tag already exists
check_tag_exists() {
    print_status "Checking if tag v$VERSION already exists..."
    
    if git tag -l "v$VERSION" | grep -q "v$VERSION"; then
        print_warning "Tag v$VERSION already exists"
        read -p "Do you want to delete the existing tag and recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Deleting existing tag..."
            git tag -d "v$VERSION"
            git push origin ":refs/tags/v$VERSION" 2>/dev/null || true
        else
            print_status "Using existing tag"
            return 0
        fi
    fi
    
    return 1
}

# Create and push tag
create_tag() {
    print_status "Creating tag v$VERSION..."
    
    # Create annotated tag
    git tag -a "v$VERSION" -m "Release v$VERSION"
    
    # Push tag to remote
    print_status "Pushing tag to remote..."
    git push origin "v$VERSION"
    
    print_success "Tag v$VERSION created and pushed"
}

# Generate release notes
generate_release_notes() {
    print_status "Generating release notes..."
    
    # Get the previous tag
    PREVIOUS_TAG=$(git describe --tags --abbrev=0 HEAD~1 2>/dev/null || echo "")
    
    if [ -z "$PREVIOUS_TAG" ]; then
        print_warning "No previous tag found, generating initial release notes"
        RELEASE_NOTES="## Initial Release v$VERSION

### Features
- Complete Leegion Framework v2.0 implementation
- Network scanning and enumeration tools
- Web application security testing
- VPN management capabilities
- Comprehensive reporting system

### Technical Improvements
- Type-safe codebase with full mypy compliance
- Modern Python packaging with pyproject.toml
- Automated CI/CD pipeline
- Comprehensive error handling
- Security-focused design

### Documentation
- Complete user manual
- API documentation
- Installation guides
- Security best practices"
    else
        print_status "Generating release notes from $PREVIOUS_TAG to v$VERSION"
        
        # Get commit messages since last tag
        COMMITS=$(git log --pretty=format:"- %s" $PREVIOUS_TAG..HEAD)
        
        RELEASE_NOTES="## Release v$VERSION

### Changes since $PREVIOUS_TAG

$COMMITS

### Technical Details
- Framework version: $VERSION
- Python compatibility: 3.8+
- Dependencies: See requirements.txt"
    fi
    
    # Save to file
    echo "$RELEASE_NOTES" > "RELEASE_NOTES_v$VERSION.md"
    print_success "Release notes saved to RELEASE_NOTES_v$VERSION.md"
}

# Create GitHub release
create_github_release() {
    print_status "Creating GitHub release..."
    
    # Check if release already exists
    if gh release view "v$VERSION" &> /dev/null; then
        print_warning "Release v$VERSION already exists"
        read -p "Do you want to delete the existing release and recreate it? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            print_status "Deleting existing release..."
            gh release delete "v$VERSION" --yes
        else
            print_status "Using existing release"
            return 0
        fi
    fi
    
    # Create release
    gh release create "v$VERSION" \
        --title "Leegion Framework v$VERSION" \
        --notes-file "RELEASE_NOTES_v$VERSION.md" \
        --draft=false \
        --prerelease=false
    
    print_success "GitHub release created successfully"
}

# Main execution
main() {
    echo "=========================================="
    echo "    Leegion Framework Release Script"
    echo "=========================================="
    echo
    
    check_prerequisites
    get_version
    
    # Check if tag exists and handle accordingly
    if check_tag_exists; then
        print_status "Using existing tag"
    else
        create_tag
    fi
    
    generate_release_notes
    create_github_release
    
    echo
    echo "=========================================="
    print_success "Release process completed successfully!"
    echo "=========================================="
    echo
    print_status "Release URL: https://github.com/$(gh repo view --json nameWithOwner -q .nameWithOwner)/releases/tag/v$VERSION"
    print_status "Release notes: RELEASE_NOTES_v$VERSION.md"
    echo
}

# Run main function
main "$@" 